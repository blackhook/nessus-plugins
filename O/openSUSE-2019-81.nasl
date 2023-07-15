#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-81.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121339);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-11713", "CVE-2018-4162", "CVE-2018-4163", "CVE-2018-4165", "CVE-2018-4191", "CVE-2018-4197", "CVE-2018-4207", "CVE-2018-4208", "CVE-2018-4209", "CVE-2018-4210", "CVE-2018-4212", "CVE-2018-4213", "CVE-2018-4299", "CVE-2018-4306", "CVE-2018-4309", "CVE-2018-4312", "CVE-2018-4314", "CVE-2018-4315", "CVE-2018-4316", "CVE-2018-4317", "CVE-2018-4318", "CVE-2018-4319", "CVE-2018-4323", "CVE-2018-4328", "CVE-2018-4345", "CVE-2018-4358", "CVE-2018-4359", "CVE-2018-4361", "CVE-2018-4372", "CVE-2018-4373", "CVE-2018-4375", "CVE-2018-4376", "CVE-2018-4378", "CVE-2018-4382", "CVE-2018-4386", "CVE-2018-4392", "CVE-2018-4416", "CVE-2018-4437", "CVE-2018-4438", "CVE-2018-4441", "CVE-2018-4442", "CVE-2018-4443", "CVE-2018-4464");

  script_name(english:"openSUSE Security Update : webkit2gtk3 (openSUSE-2019-81)");
  script_summary(english:"Check for the openSUSE-2019-81 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for webkit2gtk3 to version 2.22.5 fixes the following
issues :

Security issues fixed :

  - CVE-2018-4372, CVE-2018-4345, CVE-2018-4386,
    CVE-2018-4375, CVE-2018-4376, CVE-2018-4378,
    CVE-2018-4382, CVE-2018-4392, CVE-2018-4416,
    CVE-2018-4191, CVE-2018-4197, CVE-2018-4299,
    CVE-2018-4306, CVE-2018-4309, CVE-2018-4312,
    CVE-2018-4314, CVE-2018-4315, CVE-2018-4316,
    CVE-2018-4317, CVE-2018-4318, CVE-2018-4319,
    CVE-2018-4323, CVE-2018-4328, CVE-2018-4358,
    CVE-2018-4359, CVE-2018-4361, CVE-2018-4373,
    CVE-2018-4162, CVE-2018-4163, CVE-2018-4165,
    CVE-2018-11713, CVE-2018-4207, CVE-2018-4208,
    CVE-2018-4209, CVE-2018-4210, CVE-2018-4212,
    CVE-2018-4213, CVE-2018-4437, CVE-2018-4438,
    CVE-2018-4441, CVE-2018-4442, CVE-2018-4443,
    CVE-2018-4464 (bsc#1119558, bsc#1116998, bsc#1110279)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119558"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected webkit2gtk3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Safari Webkit JIT Exploit for iOS 7.1.2');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-minibrowser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-minibrowser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-plugin-process-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-plugin-process-gtk2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.0", reference:"libjavascriptcoregtk-4_0-18-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwebkit2gtk-4_0-37-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwebkit2gtk-4_0-37-debuginfo-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwebkit2gtk3-lang-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-JavaScriptCore-4_0-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-WebKit2-4_0-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-WebKit2WebExtension-4_0-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit-jsc-4-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit-jsc-4-debuginfo-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk-4_0-injected-bundles-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-debugsource-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-devel-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-minibrowser-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-minibrowser-debuginfo-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-plugin-process-gtk2-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-plugin-process-gtk2-debuginfo-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-32bit-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-32bit-debuginfo-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-32bit-2.22.5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-32bit-debuginfo-2.22.5-lp150.2.9.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjavascriptcoregtk-4_0-18 / libjavascriptcoregtk-4_0-18-32bit / etc");
}
