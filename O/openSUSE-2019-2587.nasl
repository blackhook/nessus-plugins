#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2587.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131533);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2019-8551",
    "CVE-2019-8558",
    "CVE-2019-8559",
    "CVE-2019-8563",
    "CVE-2019-8625",
    "CVE-2019-8674",
    "CVE-2019-8681",
    "CVE-2019-8684",
    "CVE-2019-8686",
    "CVE-2019-8687",
    "CVE-2019-8688",
    "CVE-2019-8689",
    "CVE-2019-8690",
    "CVE-2019-8707",
    "CVE-2019-8710",
    "CVE-2019-8719",
    "CVE-2019-8720",
    "CVE-2019-8726",
    "CVE-2019-8733",
    "CVE-2019-8735",
    "CVE-2019-8743",
    "CVE-2019-8763",
    "CVE-2019-8764",
    "CVE-2019-8765",
    "CVE-2019-8766",
    "CVE-2019-8768",
    "CVE-2019-8769",
    "CVE-2019-8771",
    "CVE-2019-8782",
    "CVE-2019-8783",
    "CVE-2019-8808",
    "CVE-2019-8811",
    "CVE-2019-8812",
    "CVE-2019-8813",
    "CVE-2019-8814",
    "CVE-2019-8815",
    "CVE-2019-8816",
    "CVE-2019-8819",
    "CVE-2019-8820",
    "CVE-2019-8821",
    "CVE-2019-8822",
    "CVE-2019-8823"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"openSUSE Security Update : webkit2gtk3 (openSUSE-2019-2587)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for webkit2gtk3 to version 2.26.2 fixes the following
issues :

Webkit2gtk3 was updated to version 2.26.2 (WSA-2019-0005 and
WSA-2019-0006, bsc#1155321 bsc#1156318) 

Security issues addressed :

  - CVE-2019-8625: Fixed a logic issue where by processing
    maliciously crafted web content may lead to universal
    cross site scripting. 

  - CVE-2019-8674: Fixed a logic issue where by processing
    maliciously crafted web content may lead to universal
    cross site scripting.

  - CVE-2019-8707: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8719: Fixed a logic issue where by processing
    maliciously crafted web content may lead to universal
    cross site scripting.

  - CVE-2019-8720: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8726: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8733: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8735: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8763: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8768: Fixed an issue where a user may be unable
    to delete browsing history items.

  - CVE-2019-8769: Fixed an issue where a maliciously
    crafted website may reveal browsing history.

  - CVE-2019-8771: Fixed an issue where a maliciously
    crafted web content may violate iframe sandboxing
    policy.

  - CVE-2019-8710: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8743: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8764: Fixed a logic issue where by processing
    maliciously crafted web content may lead to universal
    cross site scripting.

  - CVE-2019-8765: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8766: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8782: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8783: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8808: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8811: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8812: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8813: Fixed a logic issue where by processing
    maliciously crafted web content may lead to universal
    cross site scripting.

  - CVE-2019-8814: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8815: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8816: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8819: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8820: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8821: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8822: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

  - CVE-2019-8823: Fixed multiple memory corruption issues
    where by processing maliciously crafted web content may
    lead to arbitrary code execution.

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155321");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156318");
  script_set_attribute(attribute:"solution", value:
"Update the affected webkit2gtk3 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8816");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.0", reference:"libjavascriptcoregtk-4_0-18-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwebkit2gtk-4_0-37-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwebkit2gtk-4_0-37-debuginfo-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwebkit2gtk3-lang-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-JavaScriptCore-4_0-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-WebKit2-4_0-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-WebKit2WebExtension-4_0-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit-jsc-4-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit-jsc-4-debuginfo-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk-4_0-injected-bundles-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-debugsource-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-devel-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-minibrowser-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-minibrowser-debuginfo-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-32bit-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-32bit-debuginfo-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-32bit-2.26.2-lp150.2.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-32bit-debuginfo-2.26.2-lp150.2.28.1") ) flag++;

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
