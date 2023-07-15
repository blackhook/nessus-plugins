#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-129.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(145295);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-25681",
    "CVE-2020-25682",
    "CVE-2020-25683",
    "CVE-2020-25684",
    "CVE-2020-25685",
    "CVE-2020-25686",
    "CVE-2020-25687"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0003");

  script_name(english:"openSUSE Security Update : dnsmasq (openSUSE-2021-129)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for dnsmasq fixes the following issues :

  - bsc#1177077: Fixed DNSpooq vulnerabilities

  - CVE-2020-25684, CVE-2020-25685, CVE-2020-25686: Fixed
    multiple Cache Poisoning attacks.

  - CVE-2020-25681, CVE-2020-25682, CVE-2020-25683,
    CVE-2020-25687: Fixed multiple potential Heap-based
    overflows when DNSSEC is enabled.

  - Retry query to other servers on receipt of SERVFAIL
    rcode (bsc#1176076)

This update was imported from the SUSE:SLE-15-SP1:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177077");
  script_set_attribute(attribute:"solution", value:
"Update the affected dnsmasq packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25682");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dnsmasq-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dnsmasq-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dnsmasq-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dnsmasq-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"dnsmasq-2.78-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dnsmasq-debuginfo-2.78-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dnsmasq-debugsource-2.78-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dnsmasq-utils-2.78-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dnsmasq-utils-debuginfo-2.78-lp151.5.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dnsmasq / dnsmasq-debuginfo / dnsmasq-debugsource / dnsmasq-utils / etc");
}
