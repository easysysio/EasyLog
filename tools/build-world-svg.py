#!/usr/bin/env python3
# =============================================================================
# tools/build-world-svg.py — generates assets/geo/world.svg (the dashboard map)
#
# Converts Natural Earth 110m country boundaries (public domain), distributed as
# the `world-atlas` TopoJSON, into a single flat SVG with one <path> per country
# keyed by its ISO-3166-1 alpha-2 code — the same code `geo.rs` stores in the
# `country_code` column, so the server can shade a country by id alone.
#
# This is a one-off asset build, NOT part of the Rust build: the generated SVG is
# committed and compiled into the binary. Re-run it only to refresh the map.
#
#   curl -o countries-110m.json \
#     https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json
#   python3 tools/build-world-svg.py countries-110m.json assets/geo/world.svg
#
# Projection is equirectangular (plate carrée), clipped to 84°N..58°S — which
# drops Antarctica and the empty polar caps while keeping every populated
# landmass. Geometry is simplified (Douglas–Peucker) and rounded to one decimal
# to keep the asset small enough to inline into every dashboard page.
# =============================================================================

import json
import sys

# ─────────────────────────────────────────────────────────────────────────────
# Output geometry: 1000px wide, ~2.78px per degree of longitude.
# ─────────────────────────────────────────────────────────────────────────────
WIDTH = 1000.0
LAT_MAX, LAT_MIN = 84.0, -58.0
PX_PER_DEG = WIDTH / 360.0
HEIGHT = (LAT_MAX - LAT_MIN) * PX_PER_DEG

TOLERANCE = 0.35  # Douglas–Peucker tolerance, in output pixels
MIN_AREA = 0.12  # drop rings smaller than this, in square output pixels

# Antarctica lies entirely below the clip window; without this it would collapse
# into a full-width slab along the bottom edge.
SKIP_IDS = {"010"}

# Natural Earth marks a few territories with id "-99" (no ISO code) and some
# ISO-coded entries that DB-IP reports separately. Map those by name.
BY_NAME = {
    "Kosovo": "XK",
    "N. Cyprus": "CY",
    "Somaliland": "SO",
    "W. Sahara": "EH",
}


# ─────────────────────────────────────────────────────────────────────────────
# decode_arcs(topology)
# Reverses TopoJSON's delta encoding + quantization, returning each arc as a
# list of (longitude, latitude) pairs.
# ─────────────────────────────────────────────────────────────────────────────
def decode_arcs(topology):
    sx, sy = topology["transform"]["scale"]
    tx, ty = topology["transform"]["translate"]
    out = []
    for arc in topology["arcs"]:
        x = y = 0
        points = []
        for dx, dy in arc:
            x += dx
            y += dy
            points.append((x * sx + tx, y * sy + ty))
        out.append(points)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# ring_points(arc_indices, arcs)
# Stitches a TopoJSON ring's arc references into one point list. A negative
# index ~i means arc i traversed backwards.
# ─────────────────────────────────────────────────────────────────────────────
def ring_points(arc_indices, arcs):
    points = []
    for idx in arc_indices:
        arc = arcs[~idx][::-1] if idx < 0 else arcs[idx]
        points.extend(arc[1:] if points else arc)
    return points


# ─────────────────────────────────────────────────────────────────────────────
# unwrapped(points)
# Countries straddling the antimeridian (Russia's Chukotka, eastern Fiji) are
# stored as one ring that jumps between +180° and −180°. Drawn as-is, that jump
# stretches a stripe right across the map, so the ring is cut at every such jump
# and yielded as separate chains — one per side of the map — each closed along
# the edge it was cut on.
# ─────────────────────────────────────────────────────────────────────────────
def unwrapped(points):
    ring = points[:-1] if points[0] == points[-1] else list(points)
    jumps = [i for i in range(len(ring)) if abs(ring[i][0] - ring[i - 1][0]) > 180.0]
    if not jumps:
        yield ring
        return
    # Rotate so the ring starts just after a jump, then cut at the rest.
    ring = ring[jumps[0]:] + ring[: jumps[0]]
    piece = [ring[0]]
    for prev, cur in zip(ring, ring[1:]):
        if abs(cur[0] - prev[0]) > 180.0:
            yield piece
            piece = [cur]
        else:
            piece.append(cur)
    yield piece


# ─────────────────────────────────────────────────────────────────────────────
# project(lon, lat)
# Equirectangular projection into the output viewBox, clamped to the vertical
# clip window so shapes crossing it stay closed.
# ─────────────────────────────────────────────────────────────────────────────
def project(lon, lat):
    lat = max(LAT_MIN, min(LAT_MAX, lat))
    return ((lon + 180.0) * PX_PER_DEG, (LAT_MAX - lat) * PX_PER_DEG)


# ─────────────────────────────────────────────────────────────────────────────
# simplify(points, tol)
# Douglas–Peucker line simplification (iterative, so deep rings can't blow the
# recursion limit). Keeps the first and last point.
# ─────────────────────────────────────────────────────────────────────────────
def simplify(points, tol):
    if len(points) < 3:
        return points
    keep = [False] * len(points)
    keep[0] = keep[-1] = True
    stack = [(0, len(points) - 1)]
    while stack:
        first, last = stack.pop()
        if last <= first + 1:
            continue
        ax, ay = points[first]
        bx, by = points[last]
        dx, dy = bx - ax, by - ay
        norm = (dx * dx + dy * dy) ** 0.5
        far_i, far_d = -1, tol
        for i in range(first + 1, last):
            px, py = points[i]
            if norm == 0:
                d = ((px - ax) ** 2 + (py - ay) ** 2) ** 0.5
            else:
                d = abs(dy * px - dx * py + bx * ay - by * ax) / norm
            if d > far_d:
                far_i, far_d = i, d
        if far_i >= 0:
            keep[far_i] = True
            stack.append((first, far_i))
            stack.append((far_i, last))
    return [p for p, k in zip(points, keep) if k]


# ─────────────────────────────────────────────────────────────────────────────
# ring_area(points)
# Absolute polygon area (shoelace), used to drop specks too small to see.
# ─────────────────────────────────────────────────────────────────────────────
def ring_area(points):
    total = 0.0
    for i in range(len(points)):
        x1, y1 = points[i]
        x2, y2 = points[(i + 1) % len(points)]
        total += x1 * y2 - x2 * y1
    return abs(total) / 2.0


# ─────────────────────────────────────────────────────────────────────────────
# path_data(polygons, arcs)
# Builds the SVG `d` attribute for one country: every ring projected,
# simplified, area-filtered, and emitted as an M/L/Z subpath.
# ─────────────────────────────────────────────────────────────────────────────
def path_data(polygons, arcs):
    parts = []
    for rings in polygons:
        for ring in rings:
            for piece in unwrapped(ring_points(ring, arcs)):
                pts = simplify([project(lon, lat) for lon, lat in piece], TOLERANCE)
                if len(pts) < 3 or ring_area(pts) < MIN_AREA:
                    continue
                coords = [f"{x:.1f} {y:.1f}" for x, y in pts]
                parts.append("M" + "L".join(coords) + "Z")
    return "".join(parts)


def main():
    if len(sys.argv) != 3:
        sys.exit(f"usage: {sys.argv[0]} <countries-110m.json> <out.svg>")
    src, dest = sys.argv[1], sys.argv[2]

    topology = json.load(open(src))
    arcs = decode_arcs(topology)
    numeric_to_alpha2 = build_iso_table()

    paths = []
    for geom in topology["objects"]["countries"]["geometries"]:
        if str(geom.get("id", "")) in SKIP_IDS:
            continue
        name = geom.get("properties", {}).get("name", "")
        code = BY_NAME.get(name, "")
        if not code:
            try:
                code = numeric_to_alpha2.get(int(geom.get("id", -1)), "")
            except (TypeError, ValueError):
                code = ""

        if geom["type"] == "Polygon":
            polygons = [geom["arcs"]]
        elif geom["type"] == "MultiPolygon":
            polygons = geom["arcs"]
        else:
            continue

        d = path_data(polygons, arcs)
        if not d:
            continue
        # Countries without an ISO-2 code can never be shaded, but are still
        # drawn so the map has no holes.
        ident = f' id="{code}"' if code else ""
        paths.append((code or "zz", f'<path{ident} d="{d}"/>'))

    paths.sort()
    body = "\n".join(p for _, p in paths)
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH:.0f} {HEIGHT:.0f}" '
        f'role="img" aria-label="World map">\n'
        f"<!-- Country boundaries: Natural Earth (public domain), 110m, via world-atlas. -->\n"
        f"{body}\n</svg>\n"
    )
    with open(dest, "w") as f:
        f.write(svg)
    print(f"{dest}: {len(paths)} countries, {len(svg) / 1024:.1f} KB")


# ─────────────────────────────────────────────────────────────────────────────
# build_iso_table()
# ISO-3166-1 numeric → alpha-2, for every code used by Natural Earth 110m.
# ─────────────────────────────────────────────────────────────────────────────
def build_iso_table():
    packed = (
        "004AF 008AL 012DZ 016AS 020AD 024AO 028AG 031AZ 032AR 036AU 040AT 044BS 048BH 050BD "
        "051AM 052BB 056BE 060BM 064BT 068BO 070BA 072BW 076BR 084BZ 090SB 092VG 096BN 100BG "
        "104MM 108BI 112BY 116KH 120CM 124CA 132CV 136KY 140CF 144LK 148TD 152CL 156CN 158TW "
        "170CO 174KM 175YT 178CG 180CD 184CK 188CR 191HR 192CU 196CY 203CZ 204BJ 208DK 212DM "
        "214DO 218EC 222SV 226GQ 231ET 232ER 233EE 234FO 238FK 242FJ 246FI 250FR 254GF 258PF "
        "260TF 262DJ 266GA 268GE 270GM 275PS 276DE 288GH 292GI 296KI 300GR 304GL 308GD 312GP 316GU "
        "320GT 324GN 328GY 332HT 340HN 344HK 348HU 352IS 356IN 360ID 364IR 368IQ 372IE 376IL "
        "380IT 384CI 388JM 392JP 398KZ 400JO 404KE 408KP 410KR 414KW 417KG 418LA 422LB 426LS "
        "428LV 430LR 434LY 440LT 442LU 446MO 450MG 454MW 458MY 462MV 466ML 470MT 478MR 480MU "
        "484MX 492MC 496MN 498MD 499ME 500MS 504MA 508MZ 512OM 516NA 520NR 524NP 528NL 540NC "
        "548VU 554NZ 558NI 562NE 566NG 570NU 578NO 583FM 584MH 585PW 586PK 591PA 598PG 600PY "
        "604PE 608PH 616PL 620PT 624GW 626TL 630PR 634QA 638RE 642RO 643RU 646RW 652BL 654SH "
        "659KN 660AI 662LC 666PM 670VC 674SM 678ST 682SA 686SN 688RS 690SC 694SL 702SG 703SK "
        "704VN 705SI 706SO 710ZA 716ZW 724ES 728SS 729SD 732EH 740SR 744SJ 748SZ 752SE 756CH "
        "760SY 762TJ 764TH 768TG 776TO 780TT 784AE 788TN 792TR 795TM 796TC 798TV 800UG 804UA "
        "807MK 818EG 826GB 831GG 832JE 834TZ 840US 850VI 854BF 858UY 860UZ 862VE 876WF 882WS "
        "887YE 894ZM"
    )
    return {int(entry[:3]): entry[3:] for entry in packed.split()}


if __name__ == "__main__":
    main()
