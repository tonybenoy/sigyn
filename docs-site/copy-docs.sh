#!/bin/bash
# Pre-build script for mdBook. All docs now live in docs-site/src/.
# Only CONTRIBUTING.md is copied from the repo root.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"

# Copy CONTRIBUTING from root
if [ -f "$(dirname "$SCRIPT_DIR")/CONTRIBUTING.md" ]; then
    cp "$(dirname "$SCRIPT_DIR")/CONTRIBUTING.md" "$SRC_DIR/contributing.md"
fi

echo "Pre-build done"

# Generate sitemap.xml and copy static SEO files after build
generate_seo_files() {
    BOOK_DIR="$SCRIPT_DIR/book"
    [ -d "$BOOK_DIR" ] || return 0

    SITE_URL="https://sigyn.org"

    # Copy robots.txt
    cp "$SRC_DIR/robots.txt" "$BOOK_DIR/robots.txt" 2>/dev/null || true

    # Generate sitemap.xml from built HTML files
    cat > "$BOOK_DIR/sitemap.xml" <<XMLEOF
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
XMLEOF

    find "$BOOK_DIR" -name "*.html" -not -name "404.html" | sort | while read -r html; do
        path="${html#$BOOK_DIR}"
        cat >> "$BOOK_DIR/sitemap.xml" <<XMLEOF
  <url>
    <loc>${SITE_URL}${path}</loc>
    <changefreq>weekly</changefreq>
  </url>
XMLEOF
    done

    cat >> "$BOOK_DIR/sitemap.xml" <<XMLEOF
</urlset>
XMLEOF

    echo "SEO files generated in $BOOK_DIR"
}

# Run if --post-build flag is passed
if [ "${1:-}" = "--post-build" ]; then
    generate_seo_files
fi
