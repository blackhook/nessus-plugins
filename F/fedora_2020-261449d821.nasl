#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-261449d821.
#

include("compat.inc");

if (description)
{
  script_id(134988);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-9281", "CVE-2020-9440");
  script_xref(name:"FEDORA", value:"2020-261449d821");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Fedora 30 : ckeditor (2020-261449d821)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"## CKEditor 4.14

**Security Updates:**

  -
    [CVE-2020-9281](https://nvd.nist.gov/vuln/detail/CVE-202
    0-9281) Fixed XSS vulnerability in the HTML data
    processor reported by [Micha&#x142;
    Bentkowski](https://twitter.com/securitymb) of
    Securitum.

&#9;Issue summary: It was possible to execute XSS inside CKEditor
after persuading the victim to: (i) switch CKEditor to source mode,
then (ii) paste a specially crafted HTML code, prepared by the
attacker, into the opened CKEditor source area, and (iii) switch back
to WYSIWYG mode or (i) copy the specially crafted HTML code, prepared
by the attacker and (ii) paste it into CKEditor in WYSIWYG mode.

  -
    [CVE-2020-9440](https://nvd.nist.gov/vuln/detail/CVE-202
    0-9440) Fixed XSS vulnerability in the WebSpellChecker
    Dialog plugin reported by [Pham Van
    Khanh](https://twitter.com/rskvp93) from Viettel Cyber
    Security.

&#9;Issue summary: It was possible to execute XSS using CKEditor after
persuading the victim to: (i) switch CKEditor to source mode, then
(ii) paste a specially crafted HTML code, prepared by the attacker,
into the opened CKEditor source area, then (iii) switch back to
WYSIWYG mode, and (iv) preview CKEditor content outside CKEditor
editable area.

**An upgrade is highly recommended!**

New features :

  -
    [#2374](https://github.com/ckeditor/ckeditor4/issues/237
    4): Added support for pasting rich content from
    LibreOffice Writer with the [Paste from
    LibreOffice](https://ckeditor.com/cke4/addon/pastefromli
    breoffice) plugin.

  -
    [#2583](https://github.com/ckeditor/ckeditor4/issues/258
    3): Changed
    [emoji](https://ckeditor.com/cke4/addon/emoji)
    suggestion box to show the matched emoji name instead of
    an ID.

  -
    [#3748](https://github.com/ckeditor/ckeditor4/issues/374
    8): Improved the [color
    button](https://ckeditor.com/cke4/addon/colorbutton)
    state to reflect the selected editor content colors.

  -
    [#3661](https://github.com/ckeditor/ckeditor4/issues/366
    1): Improved the
    [Print](https://ckeditor.com/cke4/addon/print) plugin to
    respect styling rendered by the
    [Preview](https://ckeditor.com/cke4/addon/preview)
    plugin.

  -
    [#3547](https://github.com/ckeditor/ckeditor4/issues/354
    7): Active
    [dialog](https://ckeditor.com/cke4/addon/dialog) tab now
    has the `aria-selected='true'` attribute.

  -
    [#3441](https://github.com/ckeditor/ckeditor4/issues/344
    1): Improved
    [`widget.getClipboardHtml()`](https://ckeditor.com/docs/
    ckeditor4/latest/api/CKEDITOR_plugins_widget.html#method
    -getClipboardHtml) support for dragging and dropping
    multiple
    [widgets](https://ckeditor.com/cke4/addon/widget).

Fixed Issues :

  -
    [#3587](https://github.com/ckeditor/ckeditor4/issues/358
    7): [Edge, IE] Fixed:
    [Widget](https://ckeditor.com/cke4/addon/widget) with
    form input elements loses focus during typing.

  -
    [#3705](https://github.com/ckeditor/ckeditor4/issues/370
    5): [Safari] Fixed: Safari incorrectly removes blocks
    with the
    [`editor.extractSelectedHtml()`](https://ckeditor.com/do
    cs/ckeditor4/latest/api/CKEDITOR_editor.html#method-extr
    actSelectedHtml) method after selecting all content.

  -
    [#1306](https://github.com/ckeditor/ckeditor4/issues/130
    6): Fixed: The
    [Font](https://ckeditor.com/cke4/addon/font) plugin
    creates nested HTML `<span>` tags when reapplying the
    same font multiple times.

  -
    [#3498](https://github.com/ckeditor/ckeditor4/issues/349
    8): Fixed: The editor throws an error during the copy
    operation when a
    [widget](https://ckeditor.com/cke4/addon/widget) is
    partially selected.

  -
    [#2517](https://github.com/ckeditor/ckeditor4/issues/251
    7): [Chrome, Firefox, Safari] Fixed: Inserting a new
    image when the selection partially covers an existing
    [enhanced image](https://ckeditor.com/cke4/addon/image2)
    widget throws an error.

  -
    [#3007](https://github.com/ckeditor/ckeditor4/issues/300
    7): [Chrome, Firefox, Safari] Fixed: Cannot modify the
    editor content once the selection is released over a
    [widget](https://ckeditor.com/cke4/addon/widget).

  -
    [#3698](https://github.com/ckeditor/ckeditor4/issues/369
    8): Fixed: Cutting the selected text when a
    [widget](https://ckeditor.com/cke4/addon/widget) is
    partially selected merges paragraphs.

API Changes :

  -
    [#3387](https://github.com/ckeditor/ckeditor4/issues/338
    7): Added the
    [CKEDITOR.ui.richCombo.select()](https://ckeditor.com/do
    cs/ckeditor4/latest/api/CKEDITOR_ui_richCombo.html#metho
    d-select) method.

  -
    [#3727](https://github.com/ckeditor/ckeditor4/issues/372
    7): Added new `textColor` and `bgColor` commands that
    apply the selected color chosen by the [Color
    Button](https://ckeditor.com/cke4/addon/colorbutton)
    plugin.

  -
    [#3728](https://github.com/ckeditor/ckeditor4/issues/372
    8): Added new `font` and `fontSize` commands that apply
    the selected font style chosen by the
    [Font](https://ckeditor.com/cke4/addon/colorbutton)
    plugin.

  -
    [#3842](https://github.com/ckeditor/ckeditor4/issues/384
    2): Added the
    [`editor.getSelectedRanges()`](https://ckeditor.com/docs
    /ckeditor4/latest/api/CKEDITOR_editor.html#method-getSel
    ectedRanges) alias.

  -
    [#3775](https://github.com/ckeditor/ckeditor4/issues/377
    5): Widget
    [mask](https://ckeditor.com/docs/ckeditor4/latest/api/CK
    EDITOR_plugins_widget.html#property-mask) and
    [parts](https://ckeditor.com/docs/ckeditor4/latest/api/C
    KEDITOR_plugins_widget.html#property-parts) can now be
    refreshed dynamically via API calls.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-261449d821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/colorbutton"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/dialog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/emoji"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/font"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/image2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/pastefromlibreoffice"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/preview"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/print"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ckeditor.com/cke4/addon/widget"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_editor.html#method-extractSelectedHtml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83e48840"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_editor.html#method-getSelectedRanges
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac2ddc1e"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_plugins_widget.html#method-getClipboardHtml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1bf31ab9"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_plugins_widget.html#property-mask
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?80168bb6"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_plugins_widget.html#property-parts
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97ea65ba"
  );
  # https://ckeditor.com/docs/ckeditor4/latest/api/CKEDITOR_ui_richCombo.html#method-select
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9209d626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/1306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/2374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/2517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/2583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/3007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/3387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/3441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/3498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/3547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/3587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/3661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/3698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/3705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/3727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/3728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/3748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/3775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ckeditor/ckeditor4/issues/3842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://nvd.nist.gov/vuln/detail/CVE-2020-9281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://nvd.nist.gov/vuln/detail/CVE-2020-9440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://twitter.com/rskvp93"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://twitter.com/securitymb"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"ckeditor-4.14.0-1.fc30")) flag++;


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
