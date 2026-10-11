"""Graph exports: SVG and draw.io (``.drawio``) files of the role graph *as shown*.

The page posts its current view (graph.js ``exportView()``): the nodes and edges that are
visible after the layout and filters, their positions and sizes, and which ones are faded
by the current selection. Nothing else is looked up, so the file shows exactly what the
user is looking at; hidden elements are not in the payload and are not exported. (PNG is
rendered in the browser by cytoscape, from the same canvas.)

* SVG: self-contained, the node-type icons are embedded as ``data:`` URIs (no external
  reference), styles mirror graph.js.
* draw.io: an uncompressed ``mxfile``; AWS service nodes use the ``mxgraph.aws4`` service
  icons, the role uses ``mxgraph.aws4.role``, everything else plain shapes in the page's
  colours.

Both are built with ElementTree, so every label is escaped.
"""

from __future__ import annotations

import base64
import html
import json
import math
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

SVG_NS = "http://www.w3.org/2000/svg"
XLINK_NS = "http://www.w3.org/1999/xlink"
MAX_NODES = 3000
MAX_EDGES = 8000
MAX_LABEL = 300
MAX_COORD = 1_000_000.0
MARGIN = 30.0
FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif"

# Colours of graph.js (keep in sync).
ALLOW, DENY, MIXED, NEUTRAL = "#2f8f4e", "#c0392b", "#c27c0e", "#8a94a3"
ROLE, LINE, TEXT = "#2457c5", "#5b6573", "#1f2933"
NODE_TYPES = ("principal", "role", "user", "group", "policy", "service", "action", "resource")
EFFECTS = ("allow", "deny", "mixed", "neutral", "role", "entity")
EDGE_EFFECTS = ("Allow", "Deny", "Attached")
USER = "#0f766e"  # user and group nodes

# Node-type icons: 24x24 stroke drawings (RoleLens' own, not AWS artwork).
_ICON_PATHS = {
    "principal": '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-8 8-8s8 3.6 8 8"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-8 8-8s8 3.6 8 8"/>',
    "group": (
        '<circle cx="9" cy="8" r="3.5"/><path d="M2 20c0-3.9 3.1-7 7-7s7 3.1 7 7"/>'
        '<path d="M15.5 4.6a3.5 3.5 0 0 1 0 6.8M18 13.4c2.3.9 4 3.2 4 6.6"/>'
    ),
    "role": (
        '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2.5"/>'
        '<path d="M5.5 17c.6-1.9 2-3 3.5-3s2.9 1.1 3.5 3M15 10h4M15 14h3"/>'
    ),
    "policy": '<path d="M6 2h9l5 5v15H6z"/><path d="M14 2v6h6M9 13h8M9 17h8"/>',
    "service": '<path d="M12 2l9 5v10l-9 5-9-5V7z"/><path d="M3 7l9 5 9-5M12 12v10"/>',
    "action": '<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>',
    "resource": (
        '<ellipse cx="12" cy="5" rx="8" ry="3"/>'
        '<path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>'
    ),
}
_ICON_COLORS = {
    "principal": LINE,
    "role": "#ffffff",
    "user": "#ffffff",
    "group": "#ffffff",
    "policy": "#8c4fff",
    "service": ROLE,
    "action": TEXT,
    "resource": "#7aa116",
}

# Base node styles of graph.js; effect classes (deny / mixed) override the border.
NODE_STYLES: dict[str, dict[str, Any]] = {
    "principal": {"fill": "#e8edf3", "stroke": LINE, "shape": "round"},
    "role": {
        "fill": ROLE,
        "stroke": "#1b3f8f",
        "shape": "round",
        "color": "#ffffff",
        "weight": "700",
        "size": 13,
    },
    "user": {
        "fill": USER,
        "stroke": "#0b5752",
        "shape": "round",
        "color": "#ffffff",
        "weight": "700",
        "size": 13,
    },
    "group": {
        "fill": USER,
        "stroke": "#0b5752",
        "shape": "round",
        "color": "#ffffff",
        "weight": "700",
        "size": 12,
    },
    "policy": {"fill": "#f7f3ff", "stroke": "#8c4fff", "shape": "rect"},
    "service": {"fill": "#f6f7f9", "stroke": ROLE, "shape": "ellipse"},
    "action": {"fill": "#ffffff", "stroke": LINE, "shape": "tag", "size": 10},
    "resource": {"fill": "#ffffff", "stroke": "#7aa116", "shape": "cut", "size": 10},
}

# draw.io AWS 2021 category colours and mxgraph.aws4 service icons by IAM service prefix.
_COMPUTE, _STORAGE, _DATABASE, _APPINT = "#ED7100", "#7AA116", "#C925D1", "#E7157B"
_SECURITY, _MGMT, _ANALYTICS, _NETWORK = "#DD344C", "#E7157B", "#8C4FFF", "#8C4FFF"
_ML, _DEVTOOLS, _GENERAL = "#01A88D", "#C925D1", "#232F3E"
AWS4_SERVICES: dict[str, tuple[str, str]] = {
    "ec2": ("ec2", _COMPUTE),
    "lambda": ("lambda", _COMPUTE),
    "ecs": ("ecs", _COMPUTE),
    "eks": ("eks", _COMPUTE),
    "ecr": ("ecr", _COMPUTE),
    "batch": ("batch", _COMPUTE),
    "s3": ("s3", _STORAGE),
    "elasticfilesystem": ("elastic_file_system", _STORAGE),
    "dynamodb": ("dynamodb", _DATABASE),
    "rds": ("rds", _DATABASE),
    "elasticache": ("elasticache", _DATABASE),
    "sqs": ("sqs", _APPINT),
    "sns": ("sns", _APPINT),
    "states": ("step_functions", _APPINT),
    "events": ("eventbridge", _APPINT),
    "apigateway": ("api_gateway", _APPINT),
    "execute-api": ("api_gateway", _APPINT),
    "iam": ("identity_and_access_management", _SECURITY),
    "sts": ("identity_and_access_management", _SECURITY),
    "kms": ("key_management_service", _SECURITY),
    "secretsmanager": ("secrets_manager", _SECURITY),
    "cognito-idp": ("cognito", _SECURITY),
    "guardduty": ("guardduty", _SECURITY),
    "logs": ("cloudwatch_2", _MGMT),
    "cloudwatch": ("cloudwatch_2", _MGMT),
    "ssm": ("systems_manager", _MGMT),
    "cloudformation": ("cloudformation", _MGMT),
    "cloudtrail": ("cloudtrail", _MGMT),
    "config": ("config", _MGMT),
    "organizations": ("organizations", _MGMT),
    "kinesis": ("kinesis", _ANALYTICS),
    "firehose": ("kinesis_data_firehose", _ANALYTICS),
    "glue": ("glue", _ANALYTICS),
    "athena": ("athena", _ANALYTICS),
    "redshift": ("redshift", _ANALYTICS),
    "route53": ("route_53", _NETWORK),
    "cloudfront": ("cloudfront", _NETWORK),
    "elasticloadbalancing": ("elastic_load_balancing", _NETWORK),
    "sagemaker": ("sagemaker", _ML),
    "bedrock": ("bedrock", _ML),
    "codebuild": ("codebuild", _DEVTOOLS),
    "codecommit": ("codecommit", _DEVTOOLS),
    "codepipeline": ("codepipeline", _DEVTOOLS),
    "codedeploy": ("codedeploy", _DEVTOOLS),
}
AWS4_FALLBACK = ("management_console", _GENERAL)  # "*" and services without an icon
AWS4_ICON_SIZE = 48
# draw.io AWS shapes of the IAM principals.
AWS4_ENTITY_SHAPES = {
    "role": "mxgraph.aws4.role",
    "user": "mxgraph.aws4.user",
    "group": "mxgraph.aws4.users",
}
# Built-in draw.io shapes for the other node types (keys: NODE_STYLES "shape").
DRAWIO_SHAPES = {
    "round": "rounded=1;arcSize=20;",
    "rect": "",
    "ellipse": "ellipse;",
    "tag": "rounded=1;arcSize=40;",
    "cut": "shape=hexagon;perimeter=hexagonPerimeter2;size=0.06;",
}


class ViewError(ValueError):
    """The posted view is not usable (message is safe to show)."""


@dataclass
class VNode:
    id: str
    label: str
    type: str
    effect: str
    x: float
    y: float
    w: float
    h: float
    faded: bool = False


@dataclass
class VEdge:
    id: str
    source: str
    target: str
    effect: str
    conditional: bool = False
    label: str = ""
    faded: bool = False


@dataclass
class View:
    name: str
    nodes: list[VNode] = field(default_factory=list)
    edges: list[VEdge] = field(default_factory=list)


# -- icons ---------------------------------------------------------------------------------


def icon_svg(ntype: str) -> str:
    color = _ICON_COLORS.get(ntype, TEXT)
    return (
        f'<svg xmlns="{SVG_NS}" viewBox="0 0 24 24" width="24" height="24" fill="none" '
        f'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        f"{_ICON_PATHS.get(ntype, _ICON_PATHS['resource'])}</svg>"
    )


def icon_data_uri(ntype: str) -> str:
    return "data:image/svg+xml;base64," + base64.b64encode(icon_svg(ntype).encode()).decode()


def icon_data_uris() -> dict[str, str]:
    """Icons for the live graph (graph.js), so the page and the exports look the same."""
    return {t: icon_data_uri(t) for t in NODE_TYPES}


# -- view ----------------------------------------------------------------------------------


def _num(value: Any, low: float = -MAX_COORD, high: float = MAX_COORD) -> float:
    try:
        n = float(value)
    except (TypeError, ValueError):
        raise ViewError("invalid number in the graph view") from None
    if not math.isfinite(n):
        raise ViewError("invalid number in the graph view")
    return min(max(n, low), high)


def _text(value: Any, limit: int = MAX_LABEL) -> str:
    text = "" if value is None else str(value)
    text = "".join(ch for ch in text if ch >= " " or ch == "\t")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def parse_view(raw: str | bytes | None) -> View:
    """Validate the JSON view posted by graph.js. Unknown types / effects fall back to
    neutral styles; edges whose ends are not in the view are dropped."""
    try:
        data = json.loads(raw or "")
    except ValueError:
        raise ViewError("the graph view is not valid JSON") from None
    if not isinstance(data, dict):
        raise ViewError("the graph view must be an object")
    raw_nodes = data.get("nodes") or []
    raw_edges = data.get("edges") or []
    if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
        raise ViewError("nodes and edges must be lists")
    if not raw_nodes:
        raise ViewError("the graph view is empty (nothing visible to export)")
    if len(raw_nodes) > MAX_NODES or len(raw_edges) > MAX_EDGES:
        raise ViewError("the graph view is too large to export")
    view = View(name=_text(data.get("name"), 128) or "role")
    seen: set[str] = set()
    for n in raw_nodes:
        if not isinstance(n, dict):
            raise ViewError("invalid node in the graph view")
        nid = _text(n.get("id"), 1024)
        if not nid or nid in seen:
            continue
        seen.add(nid)
        ntype = n.get("type") if n.get("type") in NODE_TYPES else "resource"
        effect = n.get("effect") if n.get("effect") in EFFECTS else "neutral"
        view.nodes.append(
            VNode(
                id=nid,
                label=_text(n.get("label")),
                type=ntype,
                effect=effect,
                x=_num(n.get("x")),
                y=_num(n.get("y")),
                w=_num(n.get("w"), 10, 800),
                h=_num(n.get("h"), 10, 800),
                faded=bool(n.get("faded")),
            )
        )
    for e in raw_edges:
        if not isinstance(e, dict):
            raise ViewError("invalid edge in the graph view")
        source, target = _text(e.get("source"), 1024), _text(e.get("target"), 1024)
        if source not in seen or target not in seen:
            continue
        view.edges.append(
            VEdge(
                id=_text(e.get("id"), 2100),
                source=source,
                target=target,
                effect=e.get("effect") if e.get("effect") in EDGE_EFFECTS else "Attached",
                conditional=bool(e.get("conditional")),
                label=_text(e.get("label"), 120),
                faded=bool(e.get("faded")),
            )
        )
    return view


# -- SVG -----------------------------------------------------------------------------------


def node_style(n: VNode) -> dict[str, Any]:
    style = {
        "color": TEXT,
        "weight": "400",
        "size": 11,
        "width": 2,
        "dash": "",
        **NODE_STYLES[n.type],
    }
    if n.type == "action" and n.effect == "allow":
        style.update(fill="#e1f3e6", stroke=ALLOW)
    if n.effect == "deny":
        style.update(stroke=DENY, width=3)
        if n.type == "action":
            style["fill"] = "#fbe4e1"
    elif n.effect == "mixed":
        style.update(stroke=MIXED, width=3, dash="6 4")
    return style


def wrap_label(label: str, size: float, max_width: float = 150.0, max_lines: int = 6) -> list[str]:
    """Greedy wrap like cytoscape's ``text-wrap: wrap`` (prefers breaks after / : , - space)."""
    per_line = max(4, int(max_width / (size * 0.58)))
    lines: list[str] = []
    rest = label
    while len(rest) > per_line and len(lines) < max_lines - 1:
        cut = max(rest.rfind(ch, 0, per_line) for ch in " :/,-")
        cut = cut + 1 if cut > 0 else per_line
        lines.append(rest[:cut].rstrip())
        rest = rest[cut:].lstrip()
    if len(rest) > per_line:
        rest = rest[: per_line - 1] + "…"
    lines.append(rest)
    return lines


def _shape(parent: ET.Element, n: VNode, style: dict[str, Any]) -> None:
    x0, y0, x1, y1 = n.x - n.w / 2, n.y - n.h / 2, n.x + n.w / 2, n.y + n.h / 2
    attrs = {
        "fill": style["fill"],
        "stroke": style["stroke"],
        "stroke-width": _f(style["width"]),
    }
    if style["dash"]:
        attrs["stroke-dasharray"] = style["dash"]
    shape = style["shape"]
    if shape == "ellipse":
        ET.SubElement(
            parent, "ellipse", cx=_f(n.x), cy=_f(n.y), rx=_f(n.w / 2), ry=_f(n.h / 2), **attrs
        )
    elif shape == "tag":
        t = min(n.h / 2, n.w / 4)
        r = min(6.0, n.h / 4)
        d = (
            f"M{_f(x0 + r)},{_f(y0)} H{_f(x1 - t)} L{_f(x1)},{_f(n.y)} L{_f(x1 - t)},{_f(y1)} "
            f"H{_f(x0 + r)} Q{_f(x0)},{_f(y1)} {_f(x0)},{_f(y1 - r)} V{_f(y0 + r)} "
            f"Q{_f(x0)},{_f(y0)} {_f(x0 + r)},{_f(y0)} Z"
        )
        ET.SubElement(parent, "path", d=d, **attrs)
    elif shape == "cut":
        c = min(8.0, n.h / 4)
        xs = (x0 + c, x1 - c, x1, x1, x1 - c, x0 + c, x0, x0)
        ys = (y0, y0, y0 + c, y1 - c, y1, y1, y1 - c, y0 + c)
        pts = zip(xs, ys, strict=True)
        ET.SubElement(
            parent, "polygon", points=" ".join(f"{_f(px)},{_f(py)}" for px, py in pts), **attrs
        )
    else:
        rx = "6" if shape == "round" else "0"
        ET.SubElement(
            parent,
            "rect",
            x=_f(x0),
            y=_f(y0),
            width=_f(n.w),
            height=_f(n.h),
            rx=rx,
            **attrs,
        )


def _clip(n: VNode, dx: float, dy: float) -> tuple[float, float]:
    """Where the ray from the node centre along (dx, dy) leaves the node outline."""
    hw, hh = n.w / 2, n.h / 2
    if dx == 0 and dy == 0:
        return n.x, n.y
    if n.type == "service":
        t = 1 / math.hypot(dx / hw, dy / hh)
    else:
        t = min(hw / abs(dx) if dx else math.inf, hh / abs(dy) if dy else math.inf)
    return n.x + dx * t, n.y + dy * t


def _f(value: float) -> str:
    return f"{value:.1f}".rstrip("0").rstrip(".")


def _edge_paint(effect: str) -> tuple[str, float, str]:
    if effect == "Allow":
        return ALLOW, 1.6, "arrow-allow"
    if effect == "Deny":
        return DENY, 3.0, "tee-deny"
    return NEUTRAL, 1.6, "arrow-neutral"


def _markers(defs: ET.Element) -> None:
    for mid, color in (("arrow-allow", ALLOW), ("arrow-neutral", NEUTRAL)):
        m = ET.SubElement(
            defs,
            "marker",
            id=mid,
            viewBox="0 0 10 10",
            refX="10",
            refY="5",
            markerWidth="9",
            markerHeight="9",
            markerUnits="userSpaceOnUse",
            orient="auto",
        )
        ET.SubElement(m, "path", d="M0,0 L10,5 L0,10 z", fill=color)
    m = ET.SubElement(
        defs,
        "marker",
        id="tee-deny",
        viewBox="0 0 10 10",
        refX="9",
        refY="5",
        markerWidth="12",
        markerHeight="12",
        markerUnits="userSpaceOnUse",
        orient="auto",
    )
    ET.SubElement(m, "path", d="M8,0 V10", stroke=DENY, **{"stroke-width": "3"})


def _bounds(view: View) -> tuple[float, float, float, float]:
    xs0 = min(n.x - n.w / 2 for n in view.nodes) - MARGIN
    ys0 = min(n.y - n.h / 2 for n in view.nodes) - MARGIN
    xs1 = max(n.x + n.w / 2 for n in view.nodes) + MARGIN
    ys1 = max(n.y + n.h / 2 for n in view.nodes) + MARGIN
    return xs0, ys0, xs1 - xs0, ys1 - ys0


def to_svg(view: View) -> str:
    x, y, w, h = _bounds(view)
    svg = ET.Element(
        "svg",
        {
            "xmlns": SVG_NS,
            "xmlns:xlink": XLINK_NS,
            "version": "1.1",
            "width": _f(w),
            "height": _f(h),
            "viewBox": f"{_f(x)} {_f(y)} {_f(w)} {_f(h)}",
            "font-family": FONT,
        },
    )
    ET.SubElement(svg, "title").text = f"RoleLens graph: {view.name}"
    defs = ET.SubElement(svg, "defs")
    _markers(defs)
    ET.SubElement(svg, "rect", x=_f(x), y=_f(y), width=_f(w), height=_f(h), fill="#ffffff")

    nodes = {n.id: n for n in view.nodes}
    edges_g = ET.SubElement(svg, "g", {"class": "edges"})
    for e in view.edges:
        s, t = nodes[e.source], nodes[e.target]
        dx, dy = t.x - s.x, t.y - s.y
        sx, sy = _clip(s, dx, dy)
        tx, ty = _clip(t, -dx, -dy)
        color, width, marker = _edge_paint(e.effect)
        g = ET.SubElement(edges_g, "g", {"class": f"edge {e.effect.lower()}"})
        if e.faded:
            g.set("opacity", "0.15")
        line = ET.SubElement(
            g,
            "line",
            x1=_f(sx),
            y1=_f(sy),
            x2=_f(tx),
            y2=_f(ty),
            stroke=color,
            **{"stroke-width": _f(width), "marker-end": f"url(#{marker})"},
        )
        if e.conditional:
            line.set("stroke-dasharray", "6 4")
        if e.label:
            label = ET.SubElement(
                g,
                "text",
                x=_f((sx + tx) / 2),
                y=_f((sy + ty) / 2),
                fill="#535e6b",
                stroke="#ffffff",
                **{
                    "font-size": "9",
                    "text-anchor": "middle",
                    "dominant-baseline": "central",
                    "stroke-width": "3",
                    "paint-order": "stroke",
                },
            )
            label.text = e.label

    nodes_g = ET.SubElement(svg, "g", {"class": "nodes"})
    for n in view.nodes:
        style = node_style(n)
        g = ET.SubElement(nodes_g, "g", {"class": f"node {n.type} {n.effect}"})
        if n.faded:
            g.set("opacity", "0.15")
        ET.SubElement(g, "title").text = n.label
        _shape(g, n, style)
        ET.SubElement(
            g,
            "image",
            {
                "x": _f(n.x - n.w / 2 + 5),
                "y": _f(n.y - 6),
                "width": "12",
                "height": "12",
                "xlink:href": icon_data_uri(n.type),
            },
        )
        lines = wrap_label(n.label, style["size"])
        line_h = style["size"] * 1.25
        text = ET.SubElement(
            g,
            "text",
            fill=style["color"],
            **{
                "font-size": str(style["size"]),
                "font-weight": style["weight"],
                "text-anchor": "middle",
                "dominant-baseline": "central",
            },
        )
        for i, part in enumerate(lines):
            span = ET.SubElement(
                text,
                "tspan",
                x=_f(n.x + 7),
                y=_f(n.y + (i - (len(lines) - 1) / 2) * line_h),
            )
            span.text = part
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(svg, encoding="unicode")


# -- draw.io -------------------------------------------------------------------------------


def aws4_icon(service: str) -> tuple[str, str]:
    """``(resIcon name, fill colour)`` of an IAM service prefix (fallback for unknown)."""
    return AWS4_SERVICES.get(service.lower(), AWS4_FALLBACK)


def _drawio_style(parts: dict[str, Any]) -> str:
    return "".join(f"{k}={v};" for k, v in parts.items())


def _vertex_style(n: VNode) -> str:
    shape = ""
    if n.type == "service":
        icon, fill = aws4_icon(n.label)
        parts: dict[str, Any] = {
            "sketch": 0,
            "outlineConnect": 0,
            "fontColor": "#232F3E",
            "gradientColor": "none",
            "fillColor": fill,
            "strokeColor": "#ffffff",
            "dashed": 0,
            "verticalLabelPosition": "bottom",
            "verticalAlign": "top",
            "align": "center",
            "html": 1,
            "fontSize": 11,
            "aspect": "fixed",
            "pointerEvents": 1,
            "shape": "mxgraph.aws4.resourceIcon",
            "resIcon": f"mxgraph.aws4.{icon}",
        }
    elif n.type in AWS4_ENTITY_SHAPES:
        parts = {
            "sketch": 0,
            "outlineConnect": 0,
            "fontColor": "#232F3E",
            "gradientColor": "none",
            "fillColor": "#DD344C",
            "strokeColor": "none",
            "dashed": 0,
            "verticalLabelPosition": "bottom",
            "verticalAlign": "top",
            "align": "center",
            "html": 1,
            "fontSize": 13,
            "fontStyle": 1,
            "aspect": "fixed",
            "pointerEvents": 1,
            "shape": AWS4_ENTITY_SHAPES[n.type],
        }
    else:
        style = node_style(n)
        shape = DRAWIO_SHAPES[style["shape"]]
        parts = {
            "whiteSpace": "wrap",
            "html": 1,
            "fillColor": style["fill"],
            "strokeColor": style["stroke"],
            "strokeWidth": style["width"],
            "fontColor": style["color"],
            "fontSize": style["size"],
        }
        if style["dash"]:
            parts.update(dashed=1, dashPattern="6 4")
    if n.faded:
        parts.update(opacity=15, textOpacity=15)
    return shape + _drawio_style(parts)


def _edge_style(e: VEdge) -> str:
    color, width, _marker = _edge_paint(e.effect)
    parts: dict[str, Any] = {
        "edgeStyle": "none",
        "html": 1,
        "rounded": 0,
        "endArrow": "dash" if e.effect == "Deny" else "block",
        "endFill": 0 if e.effect == "Deny" else 1,
        "endSize": 8,
        "strokeColor": color,
        "strokeWidth": _f(width),
        "fontSize": 9,
        "fontColor": "#535e6b",
        "labelBackgroundColor": "#ffffff",
    }
    if e.conditional:
        parts.update(dashed=1, dashPattern="6 4")
    if e.faded:
        parts.update(opacity=15, textOpacity=15)
    return _drawio_style(parts)


def to_drawio(view: View) -> str:
    x0, y0, w, h = _bounds(view)
    mxfile = ET.Element("mxfile", host="RoleLens", type="device")
    diagram = ET.SubElement(mxfile, "diagram", id="rolelens-graph", name=view.name)
    model = ET.SubElement(
        diagram,
        "mxGraphModel",
        dx="0",
        dy="0",
        grid="1",
        gridSize="10",
        guides="1",
        tooltips="1",
        connect="1",
        arrows="1",
        fold="1",
        page="1",
        pageScale="1",
        pageWidth=str(math.ceil(w)),
        pageHeight=str(math.ceil(h)),
        math="0",
        shadow="0",
    )
    root = ET.SubElement(model, "root")
    ET.SubElement(root, "mxCell", id="0")
    ET.SubElement(root, "mxCell", id="1", parent="0")
    ids: dict[str, str] = {}
    for i, n in enumerate(view.nodes, start=1):
        cid = ids[n.id] = f"n{i}"
        if n.type == "service" or n.type in AWS4_ENTITY_SHAPES:
            # AWS icons are square, with the label below them.
            nw = nh = AWS4_ICON_SIZE
        else:
            nw, nh = n.w, n.h
        cell = ET.SubElement(
            root,
            "mxCell",
            id=cid,
            value=html.escape(n.label),
            style=_vertex_style(n),
            vertex="1",
            parent="1",
        )
        cell.set("tooltip", n.id)
        ET.SubElement(
            cell,
            "mxGeometry",
            {
                "x": _f(n.x - nw / 2 - x0),
                "y": _f(n.y - nh / 2 - y0),
                "width": _f(nw),
                "height": _f(nh),
                "as": "geometry",
            },
        )
    for i, e in enumerate(view.edges, start=1):
        cell = ET.SubElement(
            root,
            "mxCell",
            id=f"e{i}",
            value=html.escape(e.label),
            style=_edge_style(e),
            edge="1",
            parent="1",
            source=ids[e.source],
            target=ids[e.target],
        )
        ET.SubElement(cell, "mxGeometry", {"relative": "1", "as": "geometry"})
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(mxfile, encoding="unicode")
