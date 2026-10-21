# enclos brand assets

The **Home base** icon uses four open corners around a central square. The horizontal wordmark adds lowercase **enclos** to its right. All SVGs have transparent backgrounds; each light/dark pair has identical geometry.

| Asset | Use on | Color |
| --- | --- | --- |
| [enclos-icon-light.svg](enclos-icon-light.svg) | Light backgrounds, such as paper `#fafaf8` | Ink `#1b1c1e` |
| [enclos-icon-dark.svg](enclos-icon-dark.svg) | Dark backgrounds, such as charcoal `#1d1e21` | Paper `#ededeb` |
| [enclos-wordmark-light.svg](enclos-wordmark-light.svg) | Light backgrounds | Ink `#1b1c1e` |
| [enclos-wordmark-dark.svg](enclos-wordmark-dark.svg) | Dark backgrounds | Paper `#ededeb` |

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
