# Enclos brand assets

The **Home base** icon uses four open corners around a central square. Both SVGs have transparent backgrounds and identical geometry in a `64 × 64` viewBox.

| Asset | Use on | Icon color |
| --- | --- | --- |
| [enclos-icon-light.svg](enclos-icon-light.svg) | Light backgrounds, such as ivory `#f5f5ed` | Forest `#173c31` |
| [enclos-icon-dark.svg](enclos-icon-dark.svg) | Dark backgrounds, such as forest `#173c31` | Lime `#d5e6af` |

The suffix names the surrounding theme. Preserve the square proportions when resizing.

Use a picture element to follow the viewer's theme automatically:

```html
<picture>
  <source srcset="assets/enclos-icon-dark.svg" media="(prefers-color-scheme: dark)">
  <img src="assets/enclos-icon-light.svg" alt="Enclos" width="64" height="64">
</picture>
```

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="enclos-icon-dark.svg">
  <img src="enclos-icon-light.svg" alt="Enclos Home base icon" width="64" height="64">
</picture>
