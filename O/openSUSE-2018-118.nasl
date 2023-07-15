#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-118.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106549);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-4692", "CVE-2016-4743", "CVE-2016-7586", "CVE-2016-7587", "CVE-2016-7589", "CVE-2016-7592", "CVE-2016-7598", "CVE-2016-7599", "CVE-2016-7610", "CVE-2016-7623", "CVE-2016-7632", "CVE-2016-7635", "CVE-2016-7639", "CVE-2016-7641", "CVE-2016-7645", "CVE-2016-7652", "CVE-2016-7654", "CVE-2016-7656", "CVE-2017-13788", "CVE-2017-13798", "CVE-2017-13803", "CVE-2017-13856", "CVE-2017-13866", "CVE-2017-13870", "CVE-2017-2350", "CVE-2017-2354", "CVE-2017-2355", "CVE-2017-2356", "CVE-2017-2362", "CVE-2017-2363", "CVE-2017-2364", "CVE-2017-2365", "CVE-2017-2366", "CVE-2017-2369", "CVE-2017-2371", "CVE-2017-2373", "CVE-2017-2496", "CVE-2017-2510", "CVE-2017-2539", "CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2017-7006", "CVE-2017-7011", "CVE-2017-7012", "CVE-2017-7018", "CVE-2017-7019", "CVE-2017-7020", "CVE-2017-7030", "CVE-2017-7034", "CVE-2017-7037", "CVE-2017-7038", "CVE-2017-7039", "CVE-2017-7040", "CVE-2017-7041", "CVE-2017-7042", "CVE-2017-7043", "CVE-2017-7046", "CVE-2017-7048", "CVE-2017-7049", "CVE-2017-7052", "CVE-2017-7055", "CVE-2017-7056", "CVE-2017-7059", "CVE-2017-7061", "CVE-2017-7064", "CVE-2017-7081", "CVE-2017-7087", "CVE-2017-7089", "CVE-2017-7090", "CVE-2017-7091", "CVE-2017-7092", "CVE-2017-7093", "CVE-2017-7094", "CVE-2017-7095", "CVE-2017-7096", "CVE-2017-7098", "CVE-2017-7099", "CVE-2017-7100", "CVE-2017-7102", "CVE-2017-7104", "CVE-2017-7107", "CVE-2017-7109", "CVE-2017-7111", "CVE-2017-7117", "CVE-2017-7120", "CVE-2017-7142", "CVE-2017-7156", "CVE-2017-7157");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"openSUSE Security Update : webkit2gtk3 (openSUSE-2018-118) (Meltdown) (Spectre)");
  script_summary(english:"Check for the openSUSE-2018-118 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for webkit2gtk3 fixes the following issues :

Update to version 2.18.5 :

  + Disable SharedArrayBuffers from Web API.

  + Reduce the precision of 'high' resolution time to 1ms.

  + bsc#1075419 - Security fixes: includes improvements to
    mitigate the effects of Spectre and Meltdown
    (CVE-2017-5753 and CVE-2017-5715).

Update to version 2.18.4 :

  + Make WebDriver implementation more spec compliant.

  + Fix a bug when trying to remove cookies before a web
    process is spawned.

  + WebKitWebDriver process no longer links to
    libjavascriptcoregtk.

  + Fix several memory leaks in GStreamer media backend.

  + bsc#1073654 - Security fixes: CVE-2017-13866,
    CVE-2017-13870, CVE-2017-7156, CVE-2017-13856.

Update to version 2.18.3 :

  + Improve calculation of font metrics to prevent
    scrollbars from being shown unnecessarily in some cases.

  + Fix handling of null capabilities in WebDriver
    implementation.

  + Security fixes: CVE-2017-13798, CVE-2017-13788,
    CVE-2017-13803.

Update to version 2.18.2 :

  + Fix rendering of arabic text.

  + Fix a crash in the web process when decoding GIF images.

  + Fix rendering of wind in Windy.com.

  + Fix several crashes and rendering issues.

Update to version 2.18.1 :

  + Improve performance of GIF animations.

  + Fix garbled display in GMail.

  + Fix rendering of several material design icons when
    using the web font.

  + Fix flickering when resizing the window in Wayland.

  + Prevent default kerberos authentication credentials from
    being used in ephemeral sessions.

  + Fix a crash when webkit_web_resource_get_data() is
    cancelled.

  + Correctly handle touchmove and touchend events in
    WebKitWebView.

  + Fix the build with enchant 2.1.1.

  + Fix the build in HPPA and Alpha.

  + Fix several crashes and rendering issues.

  + Security fixes: CVE-2017-7081, CVE-2017-7087,
    CVE-2017-7089, CVE-2017-7090, CVE-2017-7091,
    CVE-2017-7092, CVE-2017-7093, CVE-2017-7094,
    CVE-2017-7095, CVE-2017-7096, CVE-2017-7098,
    CVE-2017-7099, CVE-2017-7100, CVE-2017-7102,
    CVE-2017-7104, CVE-2017-7107, CVE-2017-7109,
    CVE-2017-7111, CVE-2017-7117, CVE-2017-7120,
    CVE-2017-7142.

  - Enable gold linker on s390/s390x on SLE15/Tumbleweed.

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075419"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webkit2gtk3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if ( rpm_check(release:"SUSE42.3", reference:"libjavascriptcoregtk-4_0-18-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libwebkit2gtk-4_0-37-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libwebkit2gtk-4_0-37-debuginfo-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libwebkit2gtk3-lang-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-JavaScriptCore-4_0-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-WebKit2-4_0-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-WebKit2WebExtension-4_0-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"webkit-jsc-4-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"webkit-jsc-4-debuginfo-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"webkit2gtk-4_0-injected-bundles-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"webkit2gtk3-debugsource-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"webkit2gtk3-devel-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"webkit2gtk3-plugin-process-gtk2-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"webkit2gtk3-plugin-process-gtk2-debuginfo-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-32bit-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-debuginfo-32bit-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-32bit-2.18.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-debuginfo-32bit-2.18.5-8.1") ) flag++;

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
