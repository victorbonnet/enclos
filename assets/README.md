# Enclos brand assets

The **Home base** icon uses four open corners around a central square. The horizontal wordmark adds lowercase **enclos** to its right. All SVGs have transparent backgrounds; each light/dark pair has identical geometry.

| Asset | Use on | Color |
| --- | --- | --- |
| [enclos-icon-light.svg](enclos-icon-light.svg) | Light backgrounds, such as ivory `#f5f5ed` | Forest `#173c31` |
| [enclos-icon-dark.svg](enclos-icon-dark.svg) | Dark backgrounds, such as forest `#173c31` | Lime `#d5e6af` |
| [enclos-wordmark-light.svg](enclos-wordmark-light.svg) | Light backgrounds | Forest `#173c31` |
| [enclos-wordmark-dark.svg](enclos-wordmark-dark.svg) | Dark backgrounds | Lime `#d5e6af` |

The suffix names the surrounding theme. Icons use a `64 × 64` viewBox; wordmarks use `260 × 64`. Preserve their aspect ratios when resizing. The wordmark's Arial Bold lettering is converted to paths, so rendering does not depend on installed fonts.

Use a picture element to follow the viewer's theme automatically:

```html
<picture>
  <source srcset="assets/enclos-wordmark-dark.svg" media="(prefers-color-scheme: dark)">
  <img src="assets/enclos-wordmark-light.svg" alt="enclos" width="260" height="64">
</picture>
```

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="enclos-wordmark-dark.svg">
  <img src="enclos-wordmark-light.svg" alt="enclos" width="260" height="64">
</picture>
