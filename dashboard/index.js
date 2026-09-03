/**
 * Glance surfaces pane.
 *
 * A CLASSIC script, not an ES module. The dashboard loads plugin bundles with
 * a plain `<script src>` (see web_server.serve_plugin_asset), so a top-level
 * `export` here is a SyntaxError and the pane never registers. It must also
 * live inside `dashboard/`: the asset route serves only from the plugin's
 * dashboard directory and blocks traversal, so a file one level up is
 * unreachable by design.
 *
 * React comes from the host SDK rather than being bundled, and there is no
 * build step, so the tree is written with React.createElement rather than JSX.
 *
 * Polls GET /stats, which is a cache read. It does NOT poll POST /scan on a
 * timer: that would be a full disk rescan every interval, per open window.
 * Scanning is behind the button.
 */
(function () {
  "use strict";

  var API = "/api/plugins/glance-surfaces";
  var POLL_MS = 30000;

  var registry = window.__HERMES_PLUGINS__;
  var sdk = window.__HERMES_PLUGIN_SDK__;
  if (!registry || !sdk || !sdk.React) return;

  var React = sdk.React;
  var h = React.createElement;
  var useState = sdk.hooks.useState;
  var useEffect = sdk.hooks.useEffect;
  var useCallback = sdk.hooks.useCallback;

  // Host-provided fetch: handles auth in both loopback and gated modes.
  // Plugins must not hand-read window.__HERMES_SESSION_TOKEN__.
  var fetchJSON = sdk.fetchJSON;

  /**
   * Palette assigned by index over whatever categories the API reports, which
   * the API takes from the scanner's own exported CATEGORIES. Exhaustive by
   * construction: a category added in the scanner arrives with a slot already
   * assigned, and there is no second list here to forget to update.
   */
  var SWATCHES = [
    "var(--accent-1, var(--color-accent, currentColor))",
    "var(--accent-2, var(--color-info, currentColor))",
    "var(--accent-3, var(--color-success, currentColor))",
    "var(--accent-4, var(--color-warning, currentColor))",
    "var(--accent-5, var(--color-danger, currentColor))",
    "var(--accent-6, var(--color-muted, currentColor))"
  ];

  var SEVERITY_COLOR = {
    critical: "var(--color-danger, var(--color-error, currentColor))",
    high: "var(--color-warning, var(--color-danger, currentColor))",
    medium: "var(--color-info, var(--color-muted, currentColor))",
    info: "var(--color-muted, currentColor)"
  };

  function categoryColor(categories, name) {
    var i = categories.indexOf(name);
    if (i < 0) return "var(--color-muted, currentColor)";
    return SWATCHES[i % SWATCHES.length];
  }

  function GlancePane() {
    var s = useState(null);
    var stats = s[0];
    var setStats = s[1];
    var b = useState(false);
    var busy = b[0];
    var setBusy = b[1];

    var load = useCallback(function () {
      return fetchJSON(API + "/stats").then(setStats, function () {
        setStats({ unreachable: true });
      });
    }, []);

    useEffect(function () {
      load();
      var t = setInterval(load, POLL_MS);
      return function () {
        clearInterval(t);
      };
    }, [load]);

    if (!stats) return h("p", null, "Loading Glance...");
    if (stats.unreachable) return h("p", null, "Glance: stats unavailable.");

    var categories = stats.categories || [];
    var counts = stats.counts || {};
    var kids = [];

    kids.push(h("h3", { key: "t" }, "Agent surfaces"));

    if (!stats.scanner_available) {
      kids.push(
        h(
          "p",
          { key: "na", style: { color: SEVERITY_COLOR.high } },
          "glance-scanner is not on PATH. Nothing is being scanned."
        )
      );
    }

    kids.push(
      h(
        "p",
        { key: "when", style: { color: "var(--color-muted, currentColor)" } },
        stats.scanned_at
          ? "Scanned " + stats.total_scanned + " surfaces at " + stats.scanned_at +
            " under policy " + (stats.policy || "strict") + "."
          : "No scan yet."
      )
    );

    // The status chip counts NEW findings only.
    //
    // A machine whose findings were all present at install reads green, because
    // nothing has changed since Glance started watching and a permanently red
    // chip is a chip nobody looks at. The baselined tally sits beside it, plain
    // and unalarming, so "green" never means "there is nothing here".
    var newCounts = stats.new_counts || {};
    var newTotal = stats.new || 0;
    var alerting = (newCounts.critical || 0) + (newCounts.high || 0);
    kids.push(
      h(
        "div",
        {
          key: "chip",
          style: { display: "flex", gap: "0.5rem", alignItems: "baseline", flexWrap: "wrap" }
        },
        h(
          "strong",
          {
            key: "new",
            style: {
              color: alerting
                ? SEVERITY_COLOR.critical
                : "var(--color-success, var(--color-muted, currentColor))"
            }
          },
          newTotal + " new"
        ),
        stats.baselined
          ? h(
              "span",
              { key: "sep", style: { color: "var(--color-muted, currentColor)" } },
              "· " + stats.baselined + " baselined"
            )
          : null
      )
    );

    kids.push(
      h(
        "div",
        { key: "counts", style: { display: "flex", gap: "1rem", flexWrap: "wrap" } },
        ["critical", "high", "medium", "info"].map(function (sev) {
          return h(
            "span",
            { key: sev, style: { color: SEVERITY_COLOR[sev] } },
            sev + " " + (counts[sev] || 0)
          );
        })
      )
    );

    /** One section of findings. Location and category only; never evidence. */
    function section(key, title, note, items) {
      if (!items || !items.length) return null;
      return h(
        "div",
        { key: key, style: { marginTop: "0.75rem" } },
        h("h4", { key: "h", style: { margin: "0 0 0.25rem" } }, title + " (" + items.length + ")"),
        note
          ? h(
              "p",
              {
                key: "n",
                style: { margin: "0 0 0.4rem", color: "var(--color-muted, currentColor)", fontSize: "0.85em" }
              },
              note
            )
          : null,
        h(
          "ul",
          { key: "l", style: { margin: 0, paddingLeft: "1.1rem", fontSize: "0.9em" } },
          items.map(function (f) {
            var loc = f.path || "";
            if (f.line) loc = loc + ":" + f.line;
            return h(
              "li",
              { key: f.id || loc },
              h("span", { style: { color: SEVERITY_COLOR[f.severity] } }, f.severity || ""),
              " ",
              h("span", { style: { color: categoryColor(categories, f.category) } }, f.category || ""),
              " ",
              loc
            );
          })
        )
      );
    }

    kids.push(section("s-new", "New", null, stats.new_findings));

    // Baselined findings stay on the page. They were present the first time
    // Glance looked, so they are not announced to the agent -- but suppression
    // from the agent feed is not deletion, and a tool that hid them would be
    // building the blind spot it exists to prevent.
    kids.push(
      section(
        "s-base",
        "Baselined",
        "Present at first scan, so not reported to the agent. Still here, still worth reading.",
        stats.baselined_findings
      )
    );

    (stats.warnings || []).forEach(function (w, i) {
      kids.push(
        h("p", { key: "w" + i, style: { color: SEVERITY_COLOR.medium } }, w.message || "")
      );
    });

    // The scanner's own diagnosis, verbatim. "Last error" invited the reader
    // to treat it as stale noise; this is the reason there is no fresh scan,
    // and it names which of the four failures happened -- process would not
    // start, non-zero exit with the scanner's own stderr, output that is not
    // JSON, or not on PATH at all. Wrapped rather than clipped, because an
    // errno message truncated at the pane edge is the message being withheld.
    if (stats.last_error) {
      kids.push(
        h(
          "p",
          {
            key: "err",
            style: {
              color: SEVERITY_COLOR.high,
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
              fontFamily: "var(--font-mono, monospace)",
              fontSize: "0.85em"
            }
          },
          "Scan failed: " + stats.last_error
        )
      );
    }

    kids.push(
      categories.length
        ? h(
            "div",
            {
              key: "legend",
              style: { display: "flex", gap: "0.75rem", flexWrap: "wrap", fontSize: "0.85em" }
            },
            categories.map(function (c) {
              return h("span", { key: c, style: { color: categoryColor(categories, c) } }, c);
            })
          )
        : h(
            "p",
            { key: "legend", style: { color: "var(--color-muted, currentColor)" } },
            "Category list unavailable: glance-scanner was not found on PATH."
          )
    );

    kids.push(
      h(
        "button",
        {
          key: "scan",
          type: "button",
          disabled: busy || stats.scanning,
          style: { marginTop: "0.75rem" },
          onClick: function () {
            setBusy(true);
            fetchJSON(API + "/scan", { method: "POST" })
              .catch(function () {})
              .then(function () {
                setBusy(false);
                load();
              });
          }
        },
        busy || stats.scanning ? "Scanning..." : "Scan now"
      )
    );

    return h("div", null, kids);
  }

  registry.register("glance-surfaces", GlancePane);
})();
