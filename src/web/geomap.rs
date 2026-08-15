// =============================================================================
// web/geomap.rs — world-map choropleth of requests by country
//
// Shades a world map from per-country request counts. The map itself is a static
// SVG compiled into the binary (assets/geo/world.svg, one <path id="XX"> per
// ISO-3166-1 alpha-2 code — the same code `geo.rs` stores in `country_code`), so
// shading a country is just a matter of tagging its path.
//
// Per request, the SVG is rewritten in a single pass: every country that has
// traffic gets a shading class (5 log-scaled steps, so one dominant country
// doesn't flatten the rest), a Bootstrap tooltip, and — on dashboards — an <a>
// wrapper carrying the same ?country= drill-down link as the "Top countries"
// panel. Countries with no traffic are left untouched and pick up the default
// fill. No JavaScript beyond the tooltip initialization already in base.html.
// =============================================================================

use std::collections::HashMap;

use duckdb::params_from_iter;
use duckdb::types::Value;
use serde::Serialize;

use super::AppError;

// The generated world map (see tools/build-world-svg.py).
static WORLD_SVG: &str = include_str!("../../assets/geo/world.svg");

// Marks the start of a country path in the SVG.
const PATH_ID: &str = "<path id=\"";

// Number of shading steps (must match the .geo-l1..N classes in base.html).
const STEPS: i64 = 5;

// One country's traffic, as counted by a dashboard query. `code` is the ISO-2
// country code, empty for "Private network" / "Unknown"; `name` is the display
// name, which is also what the ?country= filter matches on.
pub(crate) struct CountryCount {
    pub code: String,
    pub name: String,
    pub count: i64,
}

// One step of the map legend: its shading class and the count range it covers.
#[derive(Serialize)]
pub(crate) struct LegendStep {
    class: String,
    from: i64,
    to: i64,
}

// Everything the map card needs: the shaded SVG plus its legend and footnotes.
#[derive(Serialize)]
pub(crate) struct MapView {
    svg: String,
    legend: Vec<LegendStep>,
    countries: i64, // countries placed on the map
    unlocated: i64, // requests with no country (private/unknown)
    has_data: bool,
}

// A country resolved to its shading class and tooltip/link attributes.
struct Shade<'a> {
    level: i64,
    name: &'a str,
    count: i64,
    href: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// counts(conn, table, where_clause, vals)
// Per-country request counts over the dashboard's bounded set — every country,
// not just the top N, so the map shades them all. Shares the caller's WHERE
// clause and bound values, so the map honours the active range and filters.
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) fn counts(
    conn: &duckdb::Connection,
    table: &str,
    where_clause: &str,
    vals: &[Value],
) -> Result<Vec<CountryCount>, AppError> {
    let sql = format!(
        "SELECT coalesce(country_code, ''), coalesce(nullif(country, ''), 'Unknown'), count(*) \
         FROM {table} {where_clause} GROUP BY 1, 2"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params_from_iter(vals.iter()), |r| {
            Ok(CountryCount { code: r.get(0)?, name: r.get(1)?, count: r.get(2)? })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

// ─────────────────────────────────────────────────────────────────────────────
// build(rows, href_for)
// Builds the map view from per-country counts. `href_for(country_name)` supplies
// the drill-down URL for a country; pass None for a display-only map (the home
// overview, which has no filter to drill into).
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) fn build(rows: &[CountryCount], href_for: Option<&dyn Fn(&str) -> String>) -> MapView {
    let located: Vec<&CountryCount> = rows.iter().filter(|r| !r.code.trim().is_empty()).collect();
    let unlocated: i64 = rows
        .iter()
        .filter(|r| r.code.trim().is_empty())
        .map(|r| r.count)
        .sum();
    let max = located.iter().map(|r| r.count).max().unwrap_or(0);

    let shades: HashMap<String, Shade<'_>> = located
        .iter()
        .filter(|r| r.count > 0)
        .map(|r| {
            let shade = Shade {
                level: level(r.count, max),
                name: r.name.as_str(),
                count: r.count,
                href: href_for.map(|f| f(&r.name)),
            };
            (r.code.trim().to_uppercase(), shade)
        })
        .collect();

    MapView {
        svg: shade_svg(&shades),
        legend: legend(max),
        countries: shades.len() as i64,
        unlocated,
        has_data: max > 0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// level(count, max)
// Shading step (1..=STEPS) for a count, on a log scale so that a single dominant
// country still leaves the smaller ones distinguishable.
// ─────────────────────────────────────────────────────────────────────────────
fn level(count: i64, max: i64) -> i64 {
    if count <= 0 || max <= 0 {
        return 1;
    }
    if max == 1 {
        return STEPS;
    }
    let ratio = ((count as f64) + 1.0).ln() / ((max as f64) + 1.0).ln();
    ((ratio * STEPS as f64).ceil() as i64).clamp(1, STEPS)
}

// ─────────────────────────────────────────────────────────────────────────────
// legend(max)
// The count range each shading step covers — the inverse of `level`, so the
// legend always matches the shading actually applied.
// ─────────────────────────────────────────────────────────────────────────────
fn legend(max: i64) -> Vec<LegendStep> {
    if max <= 0 {
        return Vec::new();
    }
    let mut steps = Vec::new();
    let mut from = 1;
    for step in 1..=STEPS {
        // Highest count that still shades to this step — the inverse of `level`.
        // A step covering no counts at all (common when the busiest country has
        // only a handful of requests) is left out of the legend entirely.
        let to = if step == STEPS {
            max
        } else {
            let bound = ((max as f64 + 1.0).powf(step as f64 / STEPS as f64) - 1.0).floor() as i64;
            bound.min(max)
        };
        if to >= from {
            steps.push(LegendStep { class: format!("geo-l{step}"), from, to });
            from = to + 1;
        }
    }
    steps
}

// ─────────────────────────────────────────────────────────────────────────────
// shade_svg(shades)
// Single pass over the embedded SVG: each `<path id="XX" d="…"/>` whose country
// has traffic is rewritten with its shading class, a tooltip, and (when a link
// was supplied) an <a> wrapper. Every other path is copied through untouched.
// ─────────────────────────────────────────────────────────────────────────────
fn shade_svg(shades: &HashMap<String, Shade<'_>>) -> String {
    let mut out = String::with_capacity(WORLD_SVG.len() + 4096);
    let mut rest = WORLD_SVG;

    while let Some(start) = rest.find(PATH_ID) {
        out.push_str(&rest[..start]);
        rest = &rest[start..];

        // Split off the whole `<path …/>` element and read its id.
        let Some(code_len) = rest[PATH_ID.len()..].find('"') else { break };
        let code = &rest[PATH_ID.len()..PATH_ID.len() + code_len];
        let Some(close) = rest.find("/>") else { break };
        let (element, tail) = rest.split_at(close + 2);
        rest = tail;

        let Some(shade) = shades.get(code) else {
            out.push_str(element);
            continue;
        };

        if let Some(href) = &shade.href {
            out.push_str("<a class=\"geo-hit\" href=\"");
            escape_into(href, &mut out);
            out.push_str("\">");
        }
        // Re-open the element (dropping its "/>") to append our attributes.
        out.push_str(&element[..element.len() - 2]);
        out.push_str(" class=\"geo-l");
        out.push_str(&shade.level.to_string());
        out.push_str("\" data-bs-toggle=\"tooltip\" title=\"");
        escape_into(shade.name, &mut out);
        out.push_str(" — ");
        out.push_str(&shade.count.to_string());
        out.push_str(if shade.count == 1 { " request" } else { " requests" });
        out.push_str("\"/>");
        if shade.href.is_some() {
            out.push_str("</a>");
        }
    }
    out.push_str(rest);
    out
}

// Appends `s` to `out`, escaping the characters that would break out of an
// attribute value.
fn escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(rows: &[(&str, &str, i64)]) -> Vec<CountryCount> {
        rows.iter()
            .map(|(code, name, count)| CountryCount {
                code: code.to_string(),
                name: name.to_string(),
                count: *count,
            })
            .collect()
    }

    #[test]
    fn shades_and_links_countries_with_traffic() {
        let rows = counts(&[
            ("US", "United States", 100),
            ("DE", "Germany", 1),
            ("", "Private network", 7),
        ]);
        let view = build(&rows, Some(&|name: &str| format!("/apache?country={name}")));

        assert!(view.has_data);
        assert_eq!(view.countries, 2); // the private-network rows aren't on the map
        assert_eq!(view.unlocated, 7);
        // The busiest country gets the darkest step and a drill-down link.
        assert!(view.svg.contains("href=\"/apache?country=United States\""));
        assert!(view.svg.contains("<path id=\"US\""));
        assert!(view.svg.contains("class=\"geo-l5\" data-bs-toggle=\"tooltip\" title=\"United States — 100 requests\""));
        assert!(view.svg.contains("title=\"Germany — 1 request\""));
        // A country with no traffic is left exactly as the asset had it.
        assert!(view.svg.contains("<path id=\"FR\" d=\""));
        // Every legend step is covered, ending at the maximum.
        assert_eq!(view.legend.last().map(|s| s.to), Some(100));
        assert_eq!(view.legend.first().map(|s| s.from), Some(1));
    }

    #[test]
    fn legend_steps_are_contiguous_and_match_the_shading() {
        for max in [1, 2, 5, 37, 1_000, 250_000] {
            let steps = legend(max);
            assert!(!steps.is_empty(), "max={max}");
            let mut expected_from = 1;
            for step in &steps {
                assert_eq!(step.from, expected_from, "max={max}");
                assert!(step.to >= step.from, "max={max}");
                // Both ends of a step must actually shade to that step.
                let want: i64 = step.class.trim_start_matches("geo-l").parse().unwrap();
                assert_eq!(level(step.from, max), want, "from, max={max}");
                assert_eq!(level(step.to, max), want, "to, max={max}");
                expected_from = step.to + 1;
            }
            assert_eq!(steps.last().unwrap().to, max, "max={max}");
        }
    }

    #[test]
    fn an_empty_map_has_no_shading_and_no_legend() {
        let view = build(&counts(&[("", "Unknown", 3)]), None);
        assert!(!view.has_data);
        assert!(view.legend.is_empty());
        assert_eq!(view.unlocated, 3);
        assert!(!view.svg.contains("geo-l"));
        // The base map still renders.
        assert!(view.svg.contains("<path id=\"US\""));
    }
}
