#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1025.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117656);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-12911", "CVE-2018-4261", "CVE-2018-4262", "CVE-2018-4263", "CVE-2018-4264", "CVE-2018-4265", "CVE-2018-4266", "CVE-2018-4267", "CVE-2018-4270", "CVE-2018-4271", "CVE-2018-4272", "CVE-2018-4273", "CVE-2018-4278", "CVE-2018-4284");

  script_name(english:"openSUSE Security Update : webkit2gtk3 (openSUSE-2018-1025)");
  script_summary(english:"Check for the openSUSE-2018-1025 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for webkit2gtk3 to version 2.20.5 fixes the following
issues :

Security issue fixed :

  - CVE-2018-12911: Fix off-by-one in
    xdg_mime_get_simple_globs (bsc#1101999).

  - CVE-2018-4261, CVE-2018-4262, CVE-2018-4263,
    CVE-2018-4264, CVE-2018-4265, CVE-2018-4267,
    CVE-2018-4272, CVE-2018-4284: Processing maliciously
    crafted web content may lead to arbitrary code
    execution. A memory corruption issue was addressed with
    improved memory handling.

  - CVE-2018-4266: A malicious website may be able to cause
    a denial of service. A race condition was addressed with
    additional validation.

  - CVE-2018-4270, CVE-2018-4271, CVE-2018-4273: Processing
    maliciously crafted web content may lead to an
    unexpected application crash. A memory corruption issue
    was addressed with improved input validation.

  - CVE-2018-4278: A malicious website may exfiltrate audio
    data cross-origin. Sound fetched through audio elements
    may be exfiltrated cross-origin. This issue was
    addressed with improved audio taint tracking.

Other bugs fixed :

  - Fix rendering artifacts in some websites due to a bug
    introduced in 2.20.4.

  - Fix a crash when leaving accelerated compositing mode.

  - Fix non-deterministic build failure due to missing
    JavaScriptCore/JSContextRef.h.

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101999"
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
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/24");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libjavascriptcoregtk-4_0-18-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwebkit2gtk-4_0-37-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwebkit2gtk-4_0-37-debuginfo-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwebkit2gtk3-lang-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-JavaScriptCore-4_0-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-WebKit2-4_0-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-WebKit2WebExtension-4_0-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit-jsc-4-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit-jsc-4-debuginfo-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk-4_0-injected-bundles-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-debugsource-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-devel-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-plugin-process-gtk2-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-plugin-process-gtk2-debuginfo-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-32bit-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-32bit-debuginfo-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-32bit-2.20.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-32bit-debuginfo-2.20.5-lp150.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjavascriptcoregtk-4_0-18 / libjavascriptcoregtk-4_0-18-debuginfo / etc");
}
