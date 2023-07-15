#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-31ad8a36d8.
#

include("compat.inc");

if (description)
{
  script_id(122651);
  script_version("1.4");
  script_cvs_date("Date: 2020/02/06");

  script_cve_id("CVE-2018-17960", "CVE-2018-9861");
  script_xref(name:"FEDORA", value:"2019-31ad8a36d8");

  script_name(english:"Fedora 28 : ckeditor (2019-31ad8a36d8)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"## CKEditor 4.11.2

Fixed Issues :

  -
    [#2403](https://github.com/ckeditor/ckeditor-dev/issues/
    2403): Fixed: Styling inline editor initialized inside a
    table with the [Table
    Selection](https://ckeditor.com/cke4/addon/tableselectio
    n) plugin is causing style leaks.

  -
    [#2514](https://github.com/ckeditor/ckeditor-dev/issues/
    2403): Fixed: Pasting table data into inline editor
    initialized inside a table with the [Table
    Selection](https://ckeditor.com/cke4/addon/tableselectio
    n) plugin inserts pasted content into the wrapping
    table.

  -
    [#2451](https://github.com/ckeditor/ckeditor-dev/issues/
    2451): Fixed: The [Remove
    Format](https://ckeditor.com/cke4/addon/removeformat)
    plugin changes selection.

  -
    [#2546](https://github.com/ckeditor/ckeditor-dev/issues/
    2546): Fixed: The separator in the toolbar moves when
    buttons are focused.

  -
    [#2506](https://github.com/ckeditor/ckeditor-dev/issues/
    2506): Fixed: [Enhanced
    Image](https://ckeditor.com/cke4/addon/image2) throws a
    type error when an empty `<figure>` tag with an `image`
    class is upcasted.

  -
    [#2650](https://github.com/ckeditor/ckeditor-dev/issues/
    2650): Fixed:
    [Table](https://ckeditor.com/cke4/addon/table) dialog
    validator fails when the `getValue()`function is defined
    in the global scope.

  -
    [#2690](https://github.com/ckeditor/ckeditor-dev/issues/
    2690): Fixed: Decimal characters are removed from the
    inside of numbered lists when pasting content using the
    [Paste from
    Word](https://ckeditor.com/cke4/addon/pastefromword)
    plugin.

  -
    [#2205](https://github.com/ckeditor/ckeditor-dev/issues/
    2205): Fixed: It is not possible to add new list items
    under an item containing a block element.

  -
    [#2411](https://github.com/ckeditor/ckeditor-dev/issues/
    2411),
    [#2438](https://github.com/ckeditor/ckeditor-dev/issues/
    2438) Fixed: Apply numbered list option throws a console
    error for a specific markup.

  -
    [#2430](https://github.com/ckeditor/ckeditor-dev/issues/
    2430) Fixed: [Color
    Button](https://ckeditor.com/cke4/addon/colorbutton) and
    [List Block](https://ckeditor.com/cke4/addon/listblock)
    items are draggable.

Other Changes :

  - Updated the
    [WebSpellChecker](https://ckeditor.com/cke4/addon/wsc)
    (WSC) plugin :

    &#9;-
    [#52](https://github.com/WebSpellChecker/ckeditor-plugin
    -wsc/issues/52) Fixed: Clicking 'Finish Checking'
    without a prior action would hang the Spell Checking
    dialog.

  -
    [#2603](https://github.com/ckeditor/ckeditor-dev/issues/
    2603): Corrected the GPL license entry in the
    `package.json` file.

## CKEditor 4.11.1

Fixed Issues :

  -
    [#2571](https://github.com/ckeditor/ckeditor-dev/issues/
    2571): Fixed: Clicking the categories in the
    [Emoji](https://ckeditor.com/cke4/addon/emoji) dropdown
    panel scrolls the entire page.

## CKEditor 4.11

**Security Updates:**

  - Fixed XSS vulnerability in the HTML parser reported by
    [maxarr](https://hackerone.com/maxarr).

    &#9;Issue summary: It was possible to execute XSS inside
    CKEditor after persuading the victim to: (i) switch
    CKEditor to source mode, then (ii) paste a specially
    crafted HTML code, prepared by the attacker, into the
    opened CKEditor source area, and (iii) switch back to
    WYSIWYG mode.

**An upgrade is highly recommended!**

New Features :

  -
    [#2062](https://github.com/ckeditor/ckeditor-dev/pull/20
    62): Added the emoji dropdown that allows the user to
    choose the emoji from the toolbar and search for them
    using keywords.

  -
    [#2154](https://github.com/ckeditor/ckeditor-dev/issues/
    2154): The [Link](https://ckeditor.com/cke4/addon/link)
    plugin now supports phone number links.

  -
    [#1815](https://github.com/ckeditor/ckeditor-dev/issues/
    1815): The [Auto
    Link](https://ckeditor.com/cke4/addon/autolink) plugin
    supports typing link completion.

  -
    [#2478](https://github.com/ckeditor/ckeditor-dev/issues/
    2478): [Link](https://ckeditor.com/cke4/addon/link) can
    be inserted using the <kbd>Ctrl</kbd>/<kbd>Cmd</kbd> +
    <kbd>K</kbd> keystroke.

  -
    [#651](https://github.com/ckeditor/ckeditor-dev/issues/6
    51): Text pasted using the [Paste from
    Word](https://ckeditor.com/cke4/addon/pastefromword)
    plugin preserves indentation in paragraphs.

  -
    [#2248](https://github.com/ckeditor/ckeditor-dev/issues/
    2248): Added support for justification in the
    [BBCode](https://ckeditor.com/cke4/addon/bbcode) plugin.
    Thanks to [Mat&#x11B;j
    Km&iacute;nek](https://github.com/KminekMatej)!

  -
    [#706](https://github.com/ckeditor/ckeditor-dev/issues/7
    06): Added a different cursor style when selecting cells
    for the [Table
    Selection](https://ckeditor.com/cke4/addon/tableselectio
    n) plugin.

  -
    [#2072](https://github.com/ckeditor/ckeditor-dev/issues/
    2072): The [UI
    Button](https://ckeditor.com/cke4/addon/button) plugin
    supports custom `aria-haspopup` property values. The
    [Menu
    Button](https://ckeditor.com/cke4/addon/menubutton)
    `aria-haspopup` value is now `menu`, the [Panel
    Button](https://ckeditor.com/cke4/addon/panelbutton) and
    [Rich Combo](https://ckeditor.com/cke4/addon/richcombo)
    `aria-haspopup` value is now `listbox`.

  -
    [#1176](https://github.com/ckeditor/ckeditor-dev/pull/11
    76): The [Balloon
    Panel](https://ckeditor.com/cke4/addon/balloonpanel) can
    now be attached to a selection instead of an element.

  -
    [#2202](https://github.com/ckeditor/ckeditor-dev/issues/
    2202): Added the `contextmenu_contentsCss` configuration
    option to allow adding custom CSS to the [Context
    Menu](https://ckeditor.com/cke4/addon/contextmenu).

Fixed Issues :

  -
    [#1477](https://github.com/ckeditor/ckeditor-dev/issues/
    1477): Fixed: On destroy, [Balloon
    Toolbar](https://ckeditor.com/cke4/addon/balloontoolbar)
    does not destroy its content.

  -
    [#2394](https://github.com/ckeditor/ckeditor-dev/issues/
    2394): Fixed:
    [Emoji](https://ckeditor.com/cke4/addon/emoji) dropdown
    does not show up with repeated symbols in a single line.

  -
    [#1181](https://github.com/ckeditor/ckeditor-dev/issues/
    1181): [Chrome] Fixed: Opening the context menu in a
    read-only editor results in an error.

  -
    [#2276](https://github.com/ckeditor/ckeditor-dev/issues/
    2276): [iOS] Fixed:
    [Button](https://ckeditor.com/cke4/addon/button) state
    does not refresh properly.

  -
    [#1489](https://github.com/ckeditor/ckeditor-dev/issues/
    1489): Fixed: Table contents can be removed in read-only
    mode when the [Table
    Selection](https://ckeditor.com/cke4/addon/tableselectio
    n) plugin is used.

  -
    [#1264](https://github.com/ckeditor/ckeditor-dev/issues/
    1264) Fixed: Right-click does not clear the selection
    created with the [Table
    Selection](https://ckeditor.com/cke4/addon/tableselectio
    n) plugin.

  -
    [#586](https://github.com/ckeditor/ckeditor-dev/issues/5
    86) Fixed: The `required` attribute is not correctly
    recognized by the [Form
    Elements](https://ckeditor.com/cke4/addon/forms) plugin
    dialog. Thanks to [Roli
    Z&uuml;ger](https://github.com/rzueger)!

  -
    [#2380](https://github.com/ckeditor/ckeditor-dev/issues/
    2380) Fixed: Styling HTML comments in a top-level
    element results in extra paragraphs.

  -
    [#2294](https://github.com/ckeditor/ckeditor-dev/issues/
    2294) Fixed: Pasting content from Microsoft Outlook and
    then bolding it results in an error.

  -
    [#2035](https://github.com/ckeditor/ckeditor-dev/issues/
    2035) [Edge] Fixed: `Permission denied` is thrown when
    opening a [Panel](https://ckeditor.com/cke4/addon/panel)
    instance.

  -
    [#965](https://github.com/ckeditor/ckeditor-dev/issues/9
    65) Fixed: The
    [`config.forceSimpleAmpersand`](https://ckeditor.com/doc
    s/ckeditor4/latest/api/CKEDITOR_config.html#cfg-forceSim
    pleAmpersand) option does not work. Thanks to [Alex
    Maris](https://github.com/alexmaris)!

  -
    [#2448](https://github.com/ckeditor/ckeditor-dev/issues/
    2448): Fixed: The [`Escape HTML Entities`] plugin with
    custom [additional
    entities](https://ckeditor.com/docs/ckeditor4/latest/api
    /CKEDITOR_config.html#cfg-entities_additional)
    configuration breaks HTML escaping.

  -
    [#898](https://github.com/ckeditor/ckeditor-dev/issues/8
    98): Fixed: [Enhanced
    Image](https://ckeditor.com/cke4/addon/image2) long
    alternative text protrudes into the editor when the
    image is selected.

  -
    [#1113](https://github.com/ckeditor/ckeditor-dev/issues/
    1113): [Firefox] Fixed: Nested contenteditable elements
    path is not updated on focus with the [Div Editing
    Area](https://ckeditor.com/cke4/addon/divarea) plugin.

  -
    [#1682](https://github.com/ckeditor/ckeditor-dev/issues/
    1682) Fixed: Hovering the [Balloon
    Toolbar](https://ckeditor.com/cke4/addon/balloontoolbar)
    panel changes its size, causing flickering.

  -
    [#421](https://github.com/ckeditor/ckeditor-dev/issues/4
    21) Fixed: Expandable
    [Button](https://ckeditor.com/cke4/addon/button) puts
    the `(Selected)` text at the end of the label when
    clicked.

  -
    [#1454](https://github.com/ckeditor/ckeditor-dev/issues/
    1454): Fixed: The
    [`onAbort`](https://ckeditor.com/docs/ckeditor4/latest/a
    pi/CKEDITOR_fileTools_uploadWidgetDefinition.html#proper
    ty-onAbort) method of the [Upload
    Widget](https://ckeditor.com/cke4/addon/uploadwidget) is
    not called when the loader is aborted.

  -
    [#1451](https://github.com/ckeditor/ckeditor-dev/issues/
    1451): Fixed: The context menu is incorrectly positioned
    when opened with <kbd>Shift</kbd>+<kbd>F10</kbd>.

  -
    [#1722](https://github.com/ckeditor/ckeditor-dev/issues/
    1722):
    [`CKEDITOR.filter.instances`](https://ckeditor.com/docs/
    ckeditor4/latest/api/CKEDITOR_filter.html#static-propert
    y-instances) is causing memory leaks.

  -
    [#2491](https://github.com/ckeditor/ckeditor-dev/issues/
    2491): Fixed: The
    [Mentions](https://ckeditor.com/cke4/addon/mentions)
    plugin is not matching diacritic characters.

  -
    [#2519](https://github.com/ckeditor/ckeditor-dev/issues/
    2519): Fixed: The [Accessibility
    Help](https://ckeditor.com/cke4/addon/a11yhelp) dialog
    should display all available keystrokes for a single
    command.

API Changes :

  -
    [#2453](https://github.com/ckeditor/ckeditor-dev/issues/
    2453): The
    [`CKEDITOR.ui.panel.block.getItems`](https://ckeditor.co
    m/docs/ckeditor4/latest/api/CKEDITOR_ui_panel_block.html
    #method-getItems) method now also returns `input`
    elements in addition to links.

  -
    [#2224](https://github.com/ckeditor/ckeditor-dev/issues/
    2224): The
    [`CKEDITOR.tools.convertToPx`](https://ckeditor.com/docs
    /ckeditor4/latest/api/CKEDITOR_tools.html#method-convert
    ToPx) function now converts negative values.

  -
    [#2253](https://github.com/ckeditor/ckeditor-dev/issues/
    2253): The widget definition
    [`insert`](https://ckeditor.com/docs/ckeditor4/latest/ap
    i/CKEDITOR_plugins_widget_definition.html#property-inser
    t) method now passes `editor` and `commandData`. Thanks
    to [marcparmet](https://github.com/marcparmet)!

  -
    [#2045](https://github.com/ckeditor/ckeditor-dev/issues/
    2045): Extracted
    [`tools.eventsBuffer`](https://ckeditor.com/docs/ckedito
    r4/latest/api/CKEDITOR_tools.html#method-eventsBuffer)
    and
    [`tools.throttle`](https://ckeditor.com/docs/ckeditor4/l
    atest/api/CKEDITOR_tools.html#method-throttle) functions
    logic into a separate namespace.

&#9;-
[`tools.eventsBuffer`](https://ckeditor.com/docs/ckeditor4/latest/api/
CKEDITOR_tools.html#method-eventsBuffer) was extracted into
[`tools.buffers.event`](https://ckeditor.com/docs/ckeditor4/latest/api
/CKEDITOR_tools_buffers_event.html),

&#9;-
[`tools.throttle`](https://ckeditor.com/docs/ckeditor4/lates
t/api/CKEDITOR_tools.html#method-throttle) was extracted
into
[`tools.buffers.throttle`](https://ckeditor.com/docs/ckedito
r4/latest/api/CKEDITOR_tools_buffers_throttle.html).

  -
    [#2466](https://github.com/ckeditor/ckeditor-dev/issues/
    2466): The
    [`CKEDITOR.filter`](https://ckeditor.com/docs/ckeditor4/
    latest/api/CKEDITOR_tools.html#method-constructor)
    constructor accepts an additional `rules` parameter
    allowing to bind the editor and filter together.

  -
    [#2493](https://github.com/ckeditor/ckeditor-dev/issues/
    2493): The
    [`editor.getCommandKeystroke`](https://ckeditor.com/docs
    /ckeditor4/latest/api/CKEDITOR_editor.html#method-getCom
    mandKeystroke) method accepts an additional `all`
    parameter allowing to retrieve an array of all command
    keystrokes.

  -
    [#2483](https://github.com/ckeditor/ckeditor-dev/issues/
    2483): Button's DOM element created with the
    [`hasArrow`](https://ckeditor.com/docs/ckeditor4/latest/
    api/CKEDITOR_ui.html#method-addButton) definition option
    can by identified by the `.cke_button_expandable` CSS
    class.

Other Changes :

  -
    [#1713](https://github.com/ckeditor/ckeditor-dev/issues/
    1713): Removed the redundant `lang.title` entry from the
    [Clipboard](https://ckeditor.com/cke4/addon/clipboard)
    plugin.

## CKEditor 4.10.1

Fixed Issues :

  -
    [#2114](https://github.com/ckeditor/ckeditor-dev/issues/
    2114): Fixed:
    [Autocomplete](https://ckeditor.com/cke4/addon/autocompl
    ete) cannot be initialized before
    [`instanceReady`](https://ckeditor.com/docs/ckeditor4/la
    test/api/CKEDITOR_editor.html#event-instanceReady).

  -
    [#2107](https://github.com/ckeditor/ckeditor-dev/issues/
    2107): Fixed: Holding and releasing the mouse button is
    not inserting an
    [autocomplete](https://ckeditor.com/cke4/addon/autocompl
    ete) suggestion.

  -
    [#2167](https://github.com/ckeditor/ckeditor-dev/issues/
    2167): Fixed: Matching in
    [Emoji](https://ckeditor.com/cke4/addon/emoji) plugin is
    not case insensitive.

  -
    [#2195](https://github.com/ckeditor/ckeditor-dev/issues/
    2195): Fixed:
    [Emoji](https://ckeditor.com/cke4/addon/emoji) shows the
    suggestion box when the colon is preceded with other
    characters than white space.

  -
    [#2169](https://github.com/ckeditor/ckeditor-dev/issues/
    2169): [Edge] Fixed: Error thrown when pasting into the
    editor.

  -
    [#1084](https://github.com/ckeditor/ckeditor-dev/issues/
    1084) Fixed: Using the 'Automatic' option with [Color
    Button](https://ckeditor.com/cke4/addon/colorbutton) on
    a text with the color already defined sets an invalid
    color value.

  -
    [#2271](https://github.com/ckeditor/ckeditor-dev/issues/
    2271): Fixed: Custom color name not used as a label in
    the [Color
    Button](https://ckeditor.com/cke4/addon/image2) plugin.
    Thanks to [Eric Geloen](https://github.com/egeloen)!

  -
    [#2296](https://github.com/ckeditor/ckeditor-dev/issues/
    2296): Fixed: The [Color
    Button](https://ckeditor.com/cke4/addon/colorbutton)
    plugin throws an error when activated on content
    containing HTML comments.

  -
    [#966](https://github.com/ckeditor/ckeditor-dev/issues/9
    66): Fixed: Executing
    [`editor.destroy()`](https://ckeditor.com/docs/ckeditor4
    /latest/api/CKEDITOR_editor.html#method-destroy) during
    the [file
    upload](https://ckeditor.com/docs/ckeditor4/latest/api/C
    KEDITOR_fileTools_uploadWidgetDefinition.html#property-o
    nUploading) throws an error. Thanks to [Maksim
    Makarevich](https://github.com/MaksimMakarevich)!

  -
    [#1719](https://github.com/ckeditor/ckeditor-dev/issues/
    1719): Fixed: <kbd>Ctrl</kbd>/<kbd>Cmd</kbd> +
    <kbd>A</kbd> inadvertently focuses inline editor if it
    is starting and ending with a list. Thanks to
    [theNailz](https://github.com/theNailz)!

  -
    [#1046](https://github.com/ckeditor/ckeditor-dev/issues/
    1046): Fixed: Subsequent new links do not include the
    `id` attribute. Thanks to [Nathan
    Samson](https://github.com/nathansamson)!

  -
    [#1348](https://github.com/ckeditor/ckeditor-dev/issues/
    1348): Fixed: [Enhanced
    Image](https://ckeditor.com/cke4/addon/image2) plugin
    aspect ratio locking uses an old width and height on
    image URL change.

  -
    [#1791](https://github.com/ckeditor/ckeditor-dev/issues/
    1791): Fixed:
    [Image](https://ckeditor.com/cke4/addon/image) and
    [Enhanced Image](https://ckeditor.com/cke4/addon/image2)
    plugins can be enabled when [Easy
    Image](https://ckeditor.com/cke4/addon/easyimage) is
    present.

  -
    [#2254](https://github.com/ckeditor/ckeditor-dev/issues/
    2254): Fixed:
    [Image](https://ckeditor.com/cke4/addon/image) ratio
    locking is too precise for resized images. Thanks to
    [Jonathan Gilbert](https://github.com/logiclrd)!

  -
    [#1184](https://github.com/ckeditor/ckeditor-dev/issues/
    1184): [IE8-11] Fixed: Copying and pasting data in
    [read-only
    mode](https://ckeditor.com/docs/ckeditor4/latest/api/CKE
    DITOR_editor.html#property-readOnly) throws an error.

  -
    [#1916](https://github.com/ckeditor/ckeditor-dev/issues/
    1916): [IE9-11] Fixed: Pressing the <kbd>Delete</kbd>
    key in [read-only
    mode](https://ckeditor.com/docs/ckeditor4/latest/api/CKE
    DITOR_editor.html#property-readOnly) throws an error.

  -
    [#2003](https://github.com/ckeditor/ckeditor-dev/issues/
    2003): [Firefox] Fixed: Right-clicking multiple selected
    table cells containing empty paragraphs removes the
    selection.

  -
    [#1816](https://github.com/ckeditor/ckeditor-dev/issues/
    1816): Fixed: Table breaks when <kbd>Enter</kbd> is
    pressed over the [Table
    Selection](https://ckeditor.com/cke4/addon/tableselectio
    n) plugin.

  -
    [#1115](https://github.com/ckeditor/ckeditor-dev/issues/
    1115): Fixed: The `<font>` tag is not preserved when
    proper configuration is provided and a style is applied
    by the [Font](https://ckeditor.com/cke4/addon/font)
    plugin.

  -
    [#727](https://github.com/ckeditor/ckeditor-dev/issues/7
    27): Fixed: Custom styles may be invisible in the
    [Styles
    Combo](https://ckeditor.com/cke4/addon/stylescombo)
    plugin.

  -
    [#988](https://github.com/ckeditor/ckeditor-dev/issues/9
    88): Fixed: ACF-enabled custom elements prefixed with
    `object`, `embed`, `param` are removed from the editor
    content.

API Changes :

  -
    [#2249](https://github.com/ckeditor/ckeditor-dev/issues/
    1791): Added the
    [`editor.plugins.detectConflict()`](https://ckeditor.com
    /docs/ckeditor4/latest/CKEDITOR_editor_plugins.html#meth
    od-detectConflict) method finding conflicts between
    provided plugins.

## CKEditor 4.10

New Features :

  -
    [#1751](https://github.com/ckeditor/ckeditor-dev/issues/
    1751): Introduced the **Autocomplete** feature that
    consists of the following plugins :

&#9;- [Autocomplete](https://ckeditor.com/cke4/addon/autocomplete)
&ndash; Provides contextual completion feature for custom text matches
based on user input.

&#9;- [Text
Watcher](https://ckeditor.com/cke4/addon/textWatcher)
&ndash; Checks whether an editor's text change matches the
chosen criteria.

&#9;- [Text
Match](https://ckeditor.com/cke4/addon/textMatch) &ndash;
Allows to search
[`CKEDITOR.dom.range`](https://ckeditor.com/docs/ckeditor4/l
atest/api/CKEDITOR_dom_range.html) for matching text.

  -
    [#1703](https://github.com/ckeditor/ckeditor-dev/issues/
    1703): Introduced the
    [Mentions](https://ckeditor.com/cke4/addon/mentions)
    plugin providing smart completion feature for custom
    text matches based on user input starting with a chosen
    marker character.

  -
    [#1746](https://github.com/ckeditor/ckeditor-dev/issues/
    1703): Introduced the
    [Emoji](https://ckeditor.com/cke4/addon/emoji) plugin
    providing completion feature for emoji ideograms.

  -
    [#1761](https://github.com/ckeditor/ckeditor-dev/issues/
    1761): The [Auto
    Link](https://ckeditor.com/cke4/addon/autolink) plugin
    now supports email links.

Fixed Issues :

  -
    [#1458](https://github.com/ckeditor/ckeditor-dev/issues/
    1458): [Edge] Fixed: After blurring the editor it takes
    2 clicks to focus a widget.

  -
    [#1034](https://github.com/ckeditor/ckeditor-dev/issues/
    1034): Fixed: JAWS leaves forms mode after pressing the
    <kbd>Enter</kbd> key in an inline editor instance.

  -
    [#1748](https://github.com/ckeditor/ckeditor-dev/pull/17
    48): Fixed: Missing
    [`CKEDITOR.dialog.definition.onHide`](https://ckeditor.c
    om/docs/ckeditor4/latest/api/CKEDITOR_dialog_definition.
    html#property-onHide) API documentation. Thanks to
    [sunnyone](https://github.com/sunnyone)!

  -
    [#1321](https://github.com/ckeditor/ckeditor-dev/issues/
    1321): Fixed: Ideographic space character (`\u3000`) is
    lost when pasting text.

  -
    [#1776](https://github.com/ckeditor/ckeditor-dev/issues/
    1776): Fixed: Empty caption placeholder of the [Image
    Base](https://ckeditor.com/cke4/addon/imagebase) plugin
    is not hidden when blurred.

  -
    [#1592](https://github.com/ckeditor/ckeditor-dev/issues/
    1592): Fixed: The [Image
    Base](https://ckeditor.com/cke4/addon/imagebase) plugin
    caption is not visible after paste.

  -
    [#620](https://github.com/ckeditor/ckeditor-dev/issues/6
    20): Fixed: The
    [`config.forcePasteAsPlainText`](https://ckeditor.com/do
    cs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-forcePa
    steAsPlainText) option is not respected in internal and
    cross-editor pasting.

  -
    [#1467](https://github.com/ckeditor/ckeditor-dev/issues/
    1467): Fixed: The resizing cursor of the [Table
    Resize](https://ckeditor.com/cke4/addon/tableresize)
    plugin appearing in the middle of a merged cell.

API Changes :

  -
    [#850](https://github.com/ckeditor/ckeditor-dev/issues/8
    50): Backward incompatibility: Replaced the `replace`
    dialog from the [Find /
    Replace](https://ckeditor.com/cke4/addon/find) plugin
    with a `tabId` option in the `find` command.

  -
    [#1582](https://github.com/ckeditor/ckeditor-dev/issues/
    1582): The
    [`CKEDITOR.editor.addCommand()`](https://ckeditor.com/do
    cs/ckeditor4/latest/api/CKEDITOR_editor.html#method-addC
    ommand) method can now accept a
    [`CKEDITOR.command`](https://ckeditor.com/docs/ckeditor4
    /latest/api/CKEDITOR_command.html) instance as a
    parameter.

  -
    [#1712](https://github.com/ckeditor/ckeditor-dev/issues/
    1712): The
    [`extraPlugins`](https://ckeditor.com/docs/ckeditor4/lat
    est/api/CKEDITOR_config.html#cfg-extraPlugins),
    [`removePlugins`](https://ckeditor.com/docs/ckeditor4/la
    test/api/CKEDITOR_config.html#cfg-removePlugins) and
    [`plugins`](https://ckeditor.com/docs/ckeditor4/latest/a
    pi/CKEDITOR_config.html#cfg-plugins) configuration
    options allow whitespace.

  -
    [#1802](https://github.com/ckeditor/ckeditor-dev/issues/
    1802): The
    [`extraPlugins`](https://ckeditor.com/docs/ckeditor4/lat
    est/api/CKEDITOR_config.html#cfg-extraPlugins),
    [`removePlugins`](https://ckeditor.com/docs/ckeditor4/la
    test/api/CKEDITOR_config.html#cfg-removePlugins) and
    [`plugins`](https://ckeditor.com/docs/ckeditor4/latest/a
    pi/CKEDITOR_config.html#cfg-plugins) configuration
    options allow passing plugin names as an array.

  -
    [#1724](https://github.com/ckeditor/ckeditor-dev/issues/
    1724): Added an option to the
    [`getClientRect()`](https://ckeditor.com/docs/ckeditor4/
    latest/api/CKEDITOR_dom_element.html#method-getClientRec
    t) function allowing to retrieve an absolute bounding
    rectangle of the element, i.e. a position relative to
    the upper-left corner of the topmost viewport.

  -
    [#1498](https://github.com/ckeditor/ckeditor-dev/issues/
    1498) : Added a new
    [`getClientRects()`](https://ckeditor.com/docs/ckeditor4
    /latest/api/CKEDITOR_dom_range.html#method-getClientRect
    s) method to `CKEDITOR.dom.range`. It returns a list of
    rectangles for each selected element.

  -
    [#1993](https://github.com/ckeditor/ckeditor-dev/issues/
    1993): Added the
    [`CKEDITOR.tools.throttle()`](https://ckeditor.com/docs/
    ckeditor4/latest/api/CKEDITOR_tools.html#method-throttle
    ) function.

Other Changes :

  - Updated [SCAYT](https://ckeditor.com/cke4/addon/scayt)
    (Spell Check As You Type) and
    [WebSpellChecker](https://ckeditor.com/cke4/addon/wsc)
    (WSC) plugins :

    &#9;- Language dictionary update: Added support for the
    Uzbek Latin language.

    &#9;- Languages no longer supported as additional
    languages: Manx - Isle of Man (`gv_GB`) and Interlingua
    (`ia_XR`).

    &#9;- Extended and improved language dictionaries:
    Georgian and Swedish. Also added the missing word
    _'Ensure'_ to the American, British and Canada English
    language.

    &#9;-
    [#141](https://github.com/WebSpellChecker/ckeditor-plugi
    n-scayt/issues/141) Fixed: SCAYT throws 'Uncaught Error:
    Error in RangyWrappedRange module: createRange():
    Parameter must be a Window object or DOM node'.

    &#9;-
    [#153](https://github.com/WebSpellChecker/ckeditor-plugi
    n-scayt/issues/153) [Chrome] Fixed: Correcting a word in
    the widget in SCAYT moves focus to another editable.

    &#9;-
    [#155](https://github.com/WebSpellChecker/ckeditor-plugi
    n-scayt/issues/155) [IE8] Fixed: SCAYT throws an error
    and does not work.

    &#9;-
    [#156](https://github.com/WebSpellChecker/ckeditor-plugi
    n-scayt/issues/156) [IE10] Fixed: SCAYT does not seem to
    work.

    &#9;- Fixed: After some text is dragged and dropped, the
    markup is not refreshed for grammar problems in SCAYT.

    &#9;- Fixed: Request to FastCGI fails when the user
    tries to replace a word with non-English characters with
    a proper suggestion in WSC.

    &#9;- [Firefox] Fixed: <kbd>Ctrl</kbd>+<kbd>Z</kbd>
    removes focus in SCAYT.

    &#9;- Grammar support for default languages was
    improved.

    &#9;- New application source URL was added in SCAYT.

    &#9;- Removed green marks and legend related to
    grammar-supported languages in the Languages tab of
    SCAYT. Grammar is now supported for almost all the
    anguages in the list for an additional fee.

    &#9;- Fixed: JavaScript error in the console: 'Cannot
    read property 'split' of undefined' in SCAYT and WSC.

    &#9;- [IE10] Fixed: Markup is not set for a specific
    case in SCAYT.

    &#9;- Fixed: Accessibility issue: No `alt` attribute for
    the logo image in the About tab of SCAYT.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-31ad8a36d8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/a11yhelp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/autocomplete"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/autolink"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/balloonpanel"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/balloontoolbar"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/bbcode"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/button"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/clipboard"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/colorbutton"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/divarea"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/easyimage"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/emoji"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/find"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/font"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/forms"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/image"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/image2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/imagebase"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/link"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/listblock"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/mentions"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/menubutton"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/panel"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/panelbutton"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/pastefromword"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/removeformat"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/richcombo"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/scayt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/stylescombo"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/table"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/tableresize"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/tableselection"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/textMatch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/textWatcher"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/uploadwidget"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/wsc"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/CKEDITOR_editor_plugins.html#method-detectConflict
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8732ca81"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_command.html"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-entities_additional
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1051fda7"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-extraPlugins
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8729e38"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-forcePasteAsPlainText
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8df6a2a8"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-forceSimpleAmpersand
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3295a78d"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-plugins
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a88e2d1"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_config.html#cfg-removePlugins
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f3e65b7"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_dialog_definition.html#property-onHide
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8759dc2d"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_dom_element.html#method-getClientRect
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?258f37c9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_dom_range.html"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_dom_range.html#method-getClientRects
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?53e0a7fb"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_editor.html#method-addCommand
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef1def6e"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_editor.html#method-destroy
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c36739c9"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_editor.html#method-getCommandKeystroke
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?657aea16"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_editor.html#property-readOnly
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c4ef073"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_fileTools_uploadWidgetDefinition.html#property-onAbort
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2f18e65"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_fileTools_uploadWidgetDefinition.html#property-onUploading
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d45a7633"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_filter.html#static-property-instances
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ff4a700"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_plugins_widget_definition.html#property-insert
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aebd1ff0"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_tools.html#method-constructor
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4122fe2"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_tools.html#method-convertToPx
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6670592c"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_tools.html#method-eventsBuffer
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c7f158f"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_tools.html#method-throttle
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e93ba0e"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_ui.html#method-addButton
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ef06a6d"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_ui_panel_block.html#method-getItems
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dbebfa8a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/WebSpellChecker/ckeditor-plugin-scayt/issues/141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/WebSpellChecker/ckeditor-plugin-scayt/issues/153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/WebSpellChecker/ckeditor-plugin-scayt/issues/155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/WebSpellChecker/ckeditor-plugin-scayt/issues/156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/WebSpellChecker/ckeditor-plugin-wsc/issues/52"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1816"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/1993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/2690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/issues/988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/pull/1176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/pull/1748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor-dev/pull/2062"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ckeditor package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ckeditor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^28([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 28", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC28", reference:"ckeditor-4.11.2-1.fc28")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ckeditor");
}
