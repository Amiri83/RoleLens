"""SVG / draw.io graph exports: well-formed, self-contained, and exactly the posted view.

Placeholder data only (role-a, 123456789012, bucket-a)."""

import base64
import json
import xml.etree.ElementTree as ET

import pytest

from rolelens import graph_export
from rolelens.graph import build_graph
from rolelens.graph_export import ViewError, parse_view, to_drawio, to_svg

from .test_graph import MODEL

SVG = "{http://www.w3.org/2000/svg}"
XLINK_HREF = "{http://www.w3.org/1999/xlink}href"


def view_payload(graph, keep=None, faded=()):
    """What graph.js exportView() posts: visible nodes on a grid, their edges."""
    nodes, edges = [], []
    for i, el in enumerate(e for e in graph["elements"] if e["group"] == "nodes"):
        d = el["data"]
        if keep is not None and d["type"] not in keep:
            continue
        nodes.append(
            {
                "id": d["id"],
                "label": d["label"],
                "type": d["type"],
                "effect": d.get("effect", "neutral"),
                "x": (i % 4) * 200,
                "y": (i // 4) * 80,
                "w": 120,
                "h": 30,
                "faded": d["id"] in faded,
            }
        )
    ids = {n["id"] for n in nodes}
    for el in graph["elements"]:
        d = el["data"]
        if el["group"] == "edges" and d["source"] in ids and d["target"] in ids:
            edges.append({**d, "faded": False})
    return {"name": "role-a", "nodes": nodes, "edges": edges}


@pytest.fixture
def payload():
    return view_payload(build_graph(MODEL))


def test_svg_is_valid_and_self_contained(payload):
    svg = to_svg(parse_view(json.dumps(payload)))
    root = ET.fromstring(svg)
    assert root.tag == f"{SVG}svg"
    assert root.get("viewBox") and float(root.get("width")) > 0
    groups = root.findall(f".//{SVG}g[@class]")
    nodes = [g for g in groups if g.get("class").startswith("node ")]
    edges = [g for g in groups if g.get("class").startswith("edge ")]
    assert len(nodes) == len(payload["nodes"]) and len(edges) == len(payload["edges"])
    # every icon is embedded as data (and is an SVG itself); no external reference at all
    images = root.findall(f".//{SVG}image")
    assert len(images) == len(payload["nodes"])
    for img in images:
        href = img.get(XLINK_HREF)
        assert href.startswith("data:image/svg+xml;base64,")
        icon = ET.fromstring(base64.b64decode(href.split(",", 1)[1]))
        assert icon.tag == f"{SVG}svg"
    for el in root.iter():
        for key, value in el.attrib.items():
            if key in (XLINK_HREF, "href"):
                assert value.startswith("data:")
            assert "http://" not in value and "https://" not in value
    texts = "".join(root.itertext())
    assert "role-a" in texts and "s3:GetObject" in texts and "s3:::bucket-a/*" in texts
    # Deny edges use the tee marker, conditional edges are dashed
    deny = [g for g in edges if "deny" in g.get("class")]
    assert deny and all(g.find(f"{SVG}line").get("marker-end") == "url(#tee-deny)" for g in deny)
    assert any(g.find(f"{SVG}line").get("stroke-dasharray") for g in edges)


def test_exports_follow_the_view_filters_and_selection(payload):
    graph = build_graph(MODEL)
    shown = view_payload(graph, keep={"role", "policy", "service"}, faded={"service:s3"})
    view = parse_view(json.dumps(shown))
    root = ET.fromstring(to_svg(view))
    texts = "".join(root.itertext())
    assert "s3:GetObject" not in texts and "bucket-a" not in texts  # filtered out
    s3 = next(g for g in root.iter(f"{SVG}g") if g.findtext(f"{SVG}title") == "s3")
    assert s3.get("opacity") == "0.15"  # faded by the current selection
    drawio = ET.fromstring(to_drawio(view))
    vertices = drawio.findall(".//mxCell[@vertex='1']")
    assert len(vertices) == len(shown["nodes"]) < len(payload["nodes"])


def test_drawio_is_valid_mxfile_with_aws4_service_shapes(payload):
    view = parse_view(json.dumps(payload))
    root = ET.fromstring(to_drawio(view))
    assert root.tag == "mxfile"
    model = root.find("diagram/mxGraphModel")
    assert root.find("diagram").get("name") == "role-a"
    cells = model.findall("root/mxCell")
    assert [c.get("id") for c in cells[:2]] == ["0", "1"] and cells[1].get("parent") == "0"
    vertices = [c for c in cells if c.get("vertex") == "1"]
    edges = [c for c in cells if c.get("edge") == "1"]
    assert len(vertices) == len(payload["nodes"]) and len(edges) == len(payload["edges"])
    ids = {c.get("id") for c in vertices}
    assert all(e.get("source") in ids and e.get("target") in ids for e in edges)
    for c in vertices + edges:
        geo = c.find("mxGeometry")
        assert geo is not None and geo.get("as") == "geometry"
    for c in vertices:
        assert float(c.find("mxGeometry").get("x")) >= 0
    services = {c.get("value"): c.get("style") for c in vertices if "aws4" in c.get("style")}
    assert "shape=mxgraph.aws4.resourceIcon;" in services["s3"]
    assert "resIcon=mxgraph.aws4.s3;" in services["s3"]
    assert "resIcon=mxgraph.aws4.sqs;" in services["sqs"]
    assert "shape=mxgraph.aws4.role;" in services["role-a"]
    assert any("endArrow=dash;" in e.get("style") for e in edges)  # Deny


def test_labels_are_escaped():
    view = parse_view(
        json.dumps(
            {
                "name": "role-a",
                "nodes": [
                    {"id": "role", "label": "role-a <b>&", "type": "role", "x": 0, "y": 0,
                     "w": 80, "h": 30},
                    {"id": "service:unknownsvc", "label": "unknownsvc", "type": "service",
                     "effect": "allow", "x": 200, "y": 0, "w": 80, "h": 30},
                ],
                "edges": [],
            }
        )
    )  # fmt: skip
    svg = to_svg(view)
    assert "role-a &lt;b&gt;&amp;" in svg and "<b>" not in svg
    root = ET.fromstring(to_drawio(view))
    values = [c.get("value") for c in root.iter("mxCell") if c.get("vertex")]
    assert "role-a &lt;b&gt;&amp;" in values  # draw.io html=1 labels: HTML-escaped text
    unknown = next(c for c in root.iter("mxCell") if c.get("value") == "unknownsvc")
    assert "resIcon=mxgraph.aws4.management_console;" in unknown.get("style")


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "not json",
        "[]",
        json.dumps({"nodes": []}),
        json.dumps({"nodes": [{"id": "role", "type": "role", "x": "NaN", "y": 0, "w": 1, "h": 1}]}),
        json.dumps({"nodes": "role"}),
        json.dumps(
            {"nodes": [{"id": f"n{i}", "x": 0, "y": 0, "w": 1, "h": 1} for i in range(3001)]}
        ),
    ],
)
def test_parse_view_rejects_bad_input(raw):
    with pytest.raises(ViewError):
        parse_view(raw)


def test_parse_view_drops_dangling_edges_and_unknown_types():
    view = parse_view(
        json.dumps(
            {
                "nodes": [{"id": "a", "type": "evil", "effect": "x", "x": 1, "y": 2, "w": 5,
                           "h": 5000}],
                "edges": [{"id": "a->b", "source": "a", "target": "b", "effect": "Allow"}],
            }
        )
    )  # fmt: skip
    assert view.name == "role" and view.edges == []
    node = view.nodes[0]
    assert (node.type, node.effect, node.w, node.h) == ("resource", "neutral", 10, 800)


def test_icons_are_data_uris_for_every_node_type():
    icons = graph_export.icon_data_uris()
    assert set(icons) == set(graph_export.NODE_TYPES)
    assert all(uri.startswith("data:image/svg+xml;base64,") for uri in icons.values())
