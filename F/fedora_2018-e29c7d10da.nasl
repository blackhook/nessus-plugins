#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-e29c7d10da.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109712);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2018-e29c7d10da");

  script_name(english:"Fedora 27 : ckeditor (2018-e29c7d10da)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"## 4.9.2

https://ckeditor.com/cke4/release/CKEditor-4.9.2

### Security Updates

  - Fixed XSS vulnerability in the Enhanced Image (image2)
    plugin reported by Kyaw Min Thein.

  - Issue summary: It was possible to execute XSS inside
    CKEditor using the <img> tag and specially crafted HTML.
    Please note that the default presets
    (Basic/Standard/Full) do not include this plugin, so you
    are only at risk if you made a custom build and enabled
    this plugin.

## 4.9.1

https://ckeditor.com/cke4/release/CKEditor-4.9.1

### Fixed Issues

  - \#1835: Fixed: Integration between CKFinder and File
    Browser plugin does not work.

## 4.9.0

https://ckeditor.com/cke4/release/CKEditor-4.9.0

### New Features

  - \#932: Introduced Easy Image feature for inserting
    images that are automatically rescaled, optimized,
    responsive and delivered through a blazing-fast CDN.
    Three new plugins were added to support it :

  - Easy Image

  - Cloud Services

  - Image Base

  - \#1338: Keystroke labels are displayed for function keys
    (like F7, F8).

  - \#643: The File Browser plugin can now upload files
    using XHR requests. This allows for setting custom HTTP
    headers using the config.fileTools_requestHeaders
    configuration option.

  - \#1365: The File Browser plugin uses XHR requests by
    default.

  - \#1399: Added the possibility to set
    CKEDITOR.config.startupFocus as start or end to specify
    where the editor focus should be after the
    initialization.

  - \#1441: The Magic Line plugin line element can now be
    identified by the data-cke-magic-line='1' attribute.

### Fixed Issues

  - \#595: Fixed: Pasting does not work on mobile devices.

  - \#869: Fixed: Empty selection clears cached clipboard
    data in the editor.

  - \#1419: Fixed: The Widget Selection plugin selects the
    editor content with the Alt+A key combination on
    Windows.

  - \#1274: Fixed: Balloon Toolbar does not match a single
    selected image using the
    contextDefinition.cssSelectormatcher.

  - \#1232: Fixed: Balloon Toolbar buttons should be
    registered as focusable elements.

  - \#1342: Fixed: Balloon Toolbar should be re-positioned
    after the change event.

  - \#1426: [IE8-9] Fixed: Missing Balloon Toolbar
    background in the Kama skin. Thanks to Christian Elmer!

  - \#1470: Fixed: Balloon Toolbar is not visible after drag
    and drop of a widget it is attached to.

  - \#1048: Fixed: Balloon Panel is not positioned properly
    when a margin is added to its non-static parent.

  - \#889: Fixed: Unclear error message for width and height
    fields in the Image and Enhanced Image plugins.

  - \#859: Fixed: Cannot edit a link after a double-click on
    the text in the link.

  - \#1013: Fixed: Paste from Word does not work correctly
    with the config.forcePasteAsPlainText option.

  - \#1356: Fixed: Border parse function does not allow
    spaces in the color value.

  - \#1010: Fixed: The CSS border shorthand property was
    incorrectly expanded ignoring the border-color style.

  - \#1535: Fixed: Widget mouseover border contrast is
    insufficient.

  - \#1516: Fixed: Fake selection allows removing content in
    read-only mode using the Backspace and Delete keys.

  - \#1570: Fixed: Fake selection allows cutting content in
    read-only mode using the Ctrl/Cmd + X keys.

  - \#1363: Fixed: Paste notification is unclear and it
    might confuse users.

### API Changes

  - \#1346: Balloon Toolbar context manager API is now
    available in the pluginDefinition.init method of the
    requiringplugin.

  - \#1530: Added the possibility to use custom icons for
    buttons.

### Other Changes

  - Updated SCAYT (Spell Check As You Type) and
    WebSpellChecker plugins :

  - SCAYT scayt_minWordLength configuration option now
    defaults to 3 instead of 4.

  - SCAYT default number of suggested words in the context
    menu changed to 3.

  - \#90: Fixed: Selection is lost on link creation if SCAYT
    highlights the word.

  - Fixed: SCAYT crashes when the browser localStorage is
    disabled.

  - [IE11] Fixed: Unable to get property type of undefined
    or null reference error in the browser console when
    SCAYT is disabled/enabled.

  - \#46: Fixed: Editing is blocked when remote spell
    checker server is offline.

  - Fixed: User Dictionary cannot be created in WSC due to
    You already have the dictionary error.

  - Fixed: Words with apostrophe ' on the replacement make
    the WSC dialog inaccessible.

  - Fixed: SCAYT/WSC causes the Uncaught TypeError error in
    the browser console.

  - \#1337: Updated the samples layout with the new CKEditor
    4 logo and color scheme.

  - \#1591: CKBuilder and language tools are now downloaded
    over HTTPS. Thanks to August Detlefsen!

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-e29c7d10da"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ckeditor package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ckeditor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^27([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 27", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC27", reference:"ckeditor-4.9.2-1.fc27")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
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
