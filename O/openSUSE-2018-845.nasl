#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-845.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111626);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-11646", "CVE-2018-4190", "CVE-2018-4199", "CVE-2018-4218", "CVE-2018-4222", "CVE-2018-4232", "CVE-2018-4233");

  script_name(english:"openSUSE Security Update : webkit2gtk3 (openSUSE-2018-845)");
  script_summary(english:"Check for the openSUSE-2018-845 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for webkit2gtk3 to version 2.20.3 fixes the following
issues :

These security issues were fixed :

  - CVE-2018-4190: An unspecified issue allowed remote
    attackers to obtain sensitive credential information
    that is transmitted during a CSS mask-image fetch
    (bsc#1097693).

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

  - CVE-2018-11646: webkitFaviconDatabaseSetIconForPageURL
    and webkitFaviconDatabaseSetIconURLForPageURL mishandle
    an unset pageURL, leading to an application crash
    (bsc#1095611).

These non-security issues were fixed :

  - Disable Gigacage if mmap fails to allocate in Linux.

  - Add user agent quirk for paypal website.

  - Fix a network process crash when trying to get cookies
    of about:blank page.

  - Fix UI process crash when closing the window under
    Wayland.

  - Fix several crashes and rendering issues. This update
    was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097693"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webkit2gtk3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Safari Proxy Object Type Confusion');
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-plugin-process-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-plugin-process-gtk2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/10");
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

if ( rpm_check(release:"SUSE15.0", reference:"libjavascriptcoregtk-4_0-18-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwebkit2gtk-4_0-37-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwebkit2gtk-4_0-37-debuginfo-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwebkit2gtk3-lang-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-JavaScriptCore-4_0-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-WebKit2-4_0-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-WebKit2WebExtension-4_0-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit-jsc-4-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit-jsc-4-debuginfo-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk-4_0-injected-bundles-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-debugsource-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-devel-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-plugin-process-gtk2-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-plugin-process-gtk2-debuginfo-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-32bit-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-32bit-debuginfo-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-32bit-2.20.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-32bit-debuginfo-2.20.3-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjavascriptcoregtk-4_0-18 / libjavascriptcoregtk-4_0-18-debuginfo / etc");
}
