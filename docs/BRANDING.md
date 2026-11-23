# Noxmap brand assets

Noxmap uses an original mark: a bounded hexagonal field, a route-line signal,
and a centered scope point. It is not derived from Nmap or Zenmap artwork.

## Official assets

| Asset | Intended use |
| --- | --- |
| [`assets/noxmap-mark.svg`](../assets/noxmap-mark.svg) | Compact application icon, favicon, documentation mark |
| [`assets/noxmap-wordmark.svg`](../assets/noxmap-wordmark.svg) | README header, release material, social preview source |
| [`assets/noxmap-mark.png`](../assets/noxmap-mark.png) | Raster fallback |

## Use

- Preserve the mark's hexagonal boundary and clear space equal to one quarter of its width.
- Use the dark field (`#101827`), signal blue (`#2563eb`), and scope violet
  (`#8b5cf6`) together where the full mark is shown.
- Do not recolor, stretch, rotate, or combine the mark with upstream Nmap
  branding.

The wordmark uses system fonts when rendered as SVG. For a release package,
export it to a platform-appropriate raster social-preview image after the
final release title and version are known.

