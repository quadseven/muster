# site

The muster splash page. One screen, no build step, no JavaScript, no
dependencies: `index.html` is the whole page and its stylesheet.

## What ships

    index.html            the page
    _headers              Cloudflare Pages cache rules
    icons/                favicons, apple touch icon, web manifest
    icons/src/            SVG sources and the generator that draws everything

## The icons are generated, not drawn twice

`icons/src/render.py` writes both the SVG sources and every raster - the web
icons here and the Android launcher layers under
`agent/android/app/src/main/res/mipmap-*`. Run it with `python3 render.py` from
`icons/src`; it needs no dependencies, takes about a second, and is the only
way any of those files should change.

That is one script rather than an icon pipeline because the mark is four flat
polygons: no curves, no gradients, no corner rounding. Generating the vector and
the bitmaps from one set of constants is what stops them drifting apart, which
is the ordinary way an icon set rots.

It also ASSERTS the Android safe zone on every run. A launcher crops the
adaptive layer to the inner 66dp of 108dp; the mark's furthest vertex sits
30.84dp from center against a 33dp radius, 2.16dp clear. Change the geometry
past that and the script fails instead of shipping an icon that clips on
round-mask devices.

Geometry, colors and which size uses which drawing come from ICON-SPEC.md in
the design project. Note that 16 and 32 use a different drawing from 48 and up -
thicker plates on whole-pixel boundaries - so they stay crisp rather than gray.

## Deploying

Cloudflare Pages, serving this directory as the site root. There is nothing
to build - point the project at `site/` with no build command and an output
directory of `.`.

## The roster is not real

The six device rows are hardcoded sample data from the approved design. They
are illustrative and must stay that way: this page is public, and a public
page that reads a real muster would publish the fleet muster exists to keep
private. There is no fetch on this page and there should never be one.
