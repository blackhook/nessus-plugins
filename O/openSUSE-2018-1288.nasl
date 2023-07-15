#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1288.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118453);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-13884", "CVE-2017-13885", "CVE-2017-7153", "CVE-2017-7160", "CVE-2017-7161", "CVE-2017-7165", "CVE-2018-11646", "CVE-2018-11712", "CVE-2018-11713", "CVE-2018-12911", "CVE-2018-4088", "CVE-2018-4096", "CVE-2018-4101", "CVE-2018-4113", "CVE-2018-4114", "CVE-2018-4117", "CVE-2018-4118", "CVE-2018-4119", "CVE-2018-4120", "CVE-2018-4121", "CVE-2018-4122", "CVE-2018-4125", "CVE-2018-4127", "CVE-2018-4128", "CVE-2018-4129", "CVE-2018-4133", "CVE-2018-4146", "CVE-2018-4161", "CVE-2018-4162", "CVE-2018-4163", "CVE-2018-4165", "CVE-2018-4190", "CVE-2018-4199", "CVE-2018-4200", "CVE-2018-4204", "CVE-2018-4218", "CVE-2018-4222", "CVE-2018-4232", "CVE-2018-4233", "CVE-2018-4246");

  script_name(english:"openSUSE Security Update : webkit2gtk3 (openSUSE-2018-1288)");
  script_summary(english:"Check for the openSUSE-2018-1288 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for webkit2gtk3 to version 2.20.3 fixes the issues :

The following security vulnerabilities were addressed :

  - CVE-2018-12911: Fixed an off-by-one error in
    xdg_mime_get_simple_globs (boo#1101999)

  - CVE-2017-13884: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1075775).

  - CVE-2017-13885: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1075775).

  - CVE-2017-7153: An unspecified issue allowed remote
    attackers to spoof user-interface information (about
    whether the entire content is derived from a valid TLS
    session) via a crafted website that sends a 401
    Unauthorized redirect (bsc#1077535).

  - CVE-2017-7160: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1075775).

  - CVE-2017-7161: An unspecified issue allowed remote
    attackers to execute arbitrary code via special
    characters that trigger command injection (bsc#1075775,
    bsc#1077535).

  - CVE-2017-7165: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1075775).

  - CVE-2018-4088: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1075775).

  - CVE-2018-4096: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1075775).

  - CVE-2018-4200: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website that triggers a
    WebCore::jsElementScrollHeightGetter use-after-free
    (bsc#1092280).

  - CVE-2018-4204: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1092279).

  - CVE-2018-4101: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1088182).

  - CVE-2018-4113: An issue in the JavaScriptCore function
    in the 'WebKit' component allowed attackers to trigger
    an assertion failure by leveraging improper array
    indexing (bsc#1088182)

  - CVE-2018-4114: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1088182) 

  - CVE-2018-4117: An unspecified issue allowed remote
    attackers to bypass the Same Origin Policy and obtain
    sensitive information via a crafted website
    (bsc#1088182, bsc#1102530).

  - CVE-2018-4118: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1088182) 

  - CVE-2018-4119: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1088182) 

  - CVE-2018-4120: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1088182).

  - CVE-2018-4121: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1092278).

  - CVE-2018-4122: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1088182).

  - CVE-2018-4125: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1088182).

  - CVE-2018-4127: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1088182).

  - CVE-2018-4128: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1088182).

  - CVE-2018-4129: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1088182).

  - CVE-2018-4146: An unspecified issue allowed attackers to
    cause a denial of service (memory corruption) via a
    crafted website (bsc#1088182).

  - CVE-2018-4161: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1088182).

  - CVE-2018-4162: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1088182).

  - CVE-2018-4163: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1088182).

  - CVE-2018-4165: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1088182).

  - CVE-2018-4190: An unspecified issue allowed remote
    attackers to obtain sensitive credential information
    that is transmitted during a CSS mask-image fetch
    (bsc#1097693)

  - CVE-2018-4199: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (buffer overflow and application crash) via a
    crafted website (bsc#1097693)

  - CVE-2018-4218: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website that triggers an @generatorState
    use-after-free (bsc#1097693)

  - CVE-2018-4222: An unspecified issue allowed remote
    attackers to execute arbitrary code via a crafted
    website that leverages a getWasmBufferFromValue
    out-of-bounds read during WebAssembly compilation
    (bsc#1097693) 

  - CVE-2018-4232: An unspecified issue allowed remote
    attackers to overwrite cookies via a crafted website
    (bsc#1097693) 

  - CVE-2018-4233: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1097693) 

  - CVE-2018-4246: An unspecified issue allowed remote
    attackers to execute arbitrary code via a crafted
    website that leverages type confusion (bsc#1104169) 

  - CVE-2018-11646: webkitFaviconDatabaseSetIconForPageURL
    and webkitFaviconDatabaseSetIconURLForPageURL mishandled
    an unset pageURL, leading to an application crash
    (bsc#1095611)

  - CVE-2018-4133: A Safari cross-site scripting (XSS)
    vulnerability allowed remote attackers to inject
    arbitrary web script or HTML via a crafted URL
    (bsc#1088182).

  - CVE-2018-11713: The libsoup network backend of WebKit
    unexpectedly failed to use system proxy settings for
    WebSocket connections. As a result, users could be
    deanonymized by crafted websites via a WebSocket
    connection (bsc#1096060).

  - CVE-2018-11712: The libsoup network backend of WebKit
    failed to perform TLS certificate verification for
    WebSocket connections (bsc#1096061).

This update for webkit2gtk3 fixes the following issues :

  - Fixed a crash when atk_object_ref_state_set is called on
    an AtkObject that's being destroyed (bsc#1088932).

  - Fixed crash when using Wayland with QXL/virtio
    (bsc#1079512)

  - Disable Gigacage if mmap fails to allocate in Linux.

  - Add user agent quirk for paypal website.

  - Properly detect compiler flags, needed libs, and
    fallbacks for usage of 64-bit atomic operations.

  - Fix a network process crash when trying to get cookies
    of about:blank page.

  - Fix UI process crash when closing the window under
    Wayland.

  - Fix several crashes and rendering issues.

  - Do TLS error checking on
    GTlsConnection::accept-certificate to finish the load
    earlier in case of errors.

  - Properly close the connection to the nested wayland
    compositor in the Web Process.

  - Avoid painting backing stores for zero-opacity layers.

  - Fix downloads started by context menu failing in some
    websites due to missing user agent HTTP header.

  - Fix video unpause when GStreamerGL is disabled.

  - Fix several GObject introspection annotations.

  - Update user agent quiks to fix Outlook.com and
    Chase.com.

  - Fix several crashes and rendering issues.

  - Improve error message when Gigacage cannot allocate
    virtual memory.

  - Add missing WebKitWebProcessEnumTypes.h to
    webkit-web-extension.h.

  - Improve web process memory monitor thresholds.

  - Fix a web process crash when the web view is created and
    destroyed quickly.

  - Fix a network process crash when load is cancelled while
    searching for stored HTTP auth credentials.

  - Fix the build when ENABLE_VIDEO, ENABLE_WEB_AUDIO and
    ENABLE_XSLT are disabled.

  - New API to retrieve and delete cookies with
    WebKitCookieManager.

  - New web process API to detect when form is submitted via
    JavaScript.

  - Several improvements and fixes in the touch/gestures
    support.

  - Support for the &ldquo;system&rdquo; CSS font family.

  - Complex text rendering improvements and fixes.

  - More complete and spec compliant WebDriver
    implementation.

  - Ensure DNS prefetching cannot be re-enabled if disabled
    by settings.

  - Fix seek sometimes not working.

  - Fix rendering of emojis that were using the wrong scale
    factor in some cases.

  - Fix rendering of combining enclosed keycap.

  - Fix rendering scale of some layers in HiDPI.

  - Fix a crash in Wayland when closing the web view.

  - Fix crashes upower crashes when running inside a chroot
    or on systems with broken dbus/upower.

  - Fix memory leaks in GStreamer media backend when using
    GStreamer 1.14.

  - Fix several crashes and rendering issues.

  - Add ENABLE_ADDRESS_SANITIZER to make it easier to build
    with asan support.

  - Fix a crash a under Wayland when using mesa software
    rasterization.

  - Make fullscreen video work again.

  - Fix handling of missing GStreamer elements.

  - Fix rendering when webm video is played twice.

  - Fix kinetic scrolling sometimes jumping around.

  - Fix build with ICU configured without collation support.

  - WebSockets use system proxy settings now (requires
    libsoup 2.61.90).

  - Show the context menu on long-press gesture.

  - Add support for Shift + mouse scroll to scroll
    horizontally.

  - Fix zoom gesture to actually zoom instead of changing
    the page scale.

  - Implement support for Graphics ARIA roles.

  - Make sleep inhibitors work under Flatpak.

  - Add get element CSS value command to WebDriver.

  - Fix a crash aftter a swipe gesture.

  - Fix several crashes and rendering issues.

  - Fix crashes due to duplicated symbols in
    libjavascriptcoregtk and libwebkit2gtk.

  - Fix parsing of timeout values in WebDriver.

  - Implement get timeouts command in WebDriver.

  - Fix deadlock in GStreamer video sink during shutdown
    when accelerated compositing is disabled.

  - Fix several crashes and rendering issues.

  - Add web process API to detect when form is submitted via
    JavaScript.

  - Add new API to replace
    webkit_form_submission_request_get_text_fields() that is
    now deprecated.

  - Add WebKitWebView::web-process-terminated signal and
    deprecate web-process-crashed.

  - Fix rendering issues when editing text areas.

  - Use FastMalloc based GstAllocator for GStreamer.

  - Fix web process crash at startup in bmalloc.

  - Fix several memory leaks in GStreamer media backend.

  - WebKitWebDriver process no longer links to
    libjavascriptcoregtk.

  - Fix several crashes and rendering issues.

  - Add new API to add, retrieve and delete cookies via
    WebKitCookieManager.

  - Add functions to WebSettings to convert font sizes
    between points and pixels.

  - Ensure cookie operations take effect when they happen
    before a web process has been spawned.

  - Automatically adjust font size when
    GtkSettings:gtk-xft-dpi changes.

  - Add initial resource load statistics support.

  - Add API to expose availability of certain editing
    commands in WebKitEditorState.

  - Add API to query whether a WebKitNavigationAction is a
    redirect or not.

  - Improve complex text rendering.

  - Add support for the 'system' CSS font family.

  - Disable USE_GSTREAMER_GL

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104169"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webkit2gtk3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Safari Proxy Object Type Confusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk3-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-JavaScriptCore-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-WebKit2-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-WebKit2WebExtension-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit-jsc-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit-jsc-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk-4_0-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk-4_0-injected-bundles-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-plugin-process-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-plugin-process-gtk2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libjavascriptcoregtk-4_0-18-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libwebkit2gtk-4_0-37-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libwebkit2gtk-4_0-37-debuginfo-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libwebkit2gtk3-lang-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-JavaScriptCore-4_0-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-WebKit2-4_0-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-WebKit2WebExtension-4_0-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"webkit-jsc-4-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"webkit-jsc-4-debuginfo-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"webkit2gtk-4_0-injected-bundles-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"webkit2gtk3-debugsource-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"webkit2gtk3-devel-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"webkit2gtk3-plugin-process-gtk2-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"webkit2gtk3-plugin-process-gtk2-debuginfo-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-32bit-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-debuginfo-32bit-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-32bit-2.20.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-debuginfo-32bit-2.20.3-11.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjavascriptcoregtk-4_0-18 / libjavascriptcoregtk-4_0-18-32bit / etc");
}
