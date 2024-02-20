# typst-cvss-calculator

A small plugin for typst that can calculate CVSS scores from a CVSS vector.

## How to use

Using this plugin is relatively straight forward.
Simply copy the file `cvss.typ` into your project directory and you can use
it with the following lines below.
The plugin will automatically detect whether values for both a the temporal and environmental score
are present and adjust the displayed graph accordingly.

```typst
#import "cvss.typ": cvss
#cvss("VECTOR")

//Example:

#cvss("AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H")
```

## Preview

![Preview](./img/preview.png)

