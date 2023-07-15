#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-643.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(136461);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/18");

  script_cve_id("CVE-2020-12387", "CVE-2020-12392", "CVE-2020-12393", "CVE-2020-12395", "CVE-2020-12397", "CVE-2020-6831");
  script_xref(name:"IAVA", value:"2020-A-0190-S");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2020-643)");
  script_summary(english:"Check for the openSUSE-2020-643 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaThunderbird fixes the following issues :

  - Update to 68.8.0 ESR MFSA 2020-18 (bsc#1171186)

  - CVE-2020-12397 (bmo#1617370) Sender Email Address
    Spoofing using encoded Unicode characters

  - CVE-2020-12387 (bmo#1545345) Use-after-free during
    worker shutdown

  - CVE-2020-6831 (bmo#1632241) Buffer overflow in SCTP
    chunk input validation

  - CVE-2020-12392 (bmo#1614468) Arbitrary local file access
    with 'Copy as cURL'

  - CVE-2020-12393 (bmo#1615471) Devtools' 'Copy as cURL'
    feature did not fully escape website-controlled data,
    potentially leading to command injection

  - CVE-2020-12395 (bmo#1595886, bmo#1611482, bmo#1614704,
    bmo#1624098, bmo#1625749, bmo#1626382, bmo#1628076,
    bmo#1631508) Memory safety bugs fixed in Thunderbird
    68.8.0

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171186"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12395");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-68.8.0-lp151.2.38.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-debuginfo-68.8.0-lp151.2.38.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-debugsource-68.8.0-lp151.2.38.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-translations-common-68.8.0-lp151.2.38.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-translations-other-68.8.0-lp151.2.38.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-debuginfo / etc");
}
