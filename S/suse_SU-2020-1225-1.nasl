#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1225-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(136658);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/18");

  script_cve_id("CVE-2020-12387", "CVE-2020-12392", "CVE-2020-12393", "CVE-2020-12395", "CVE-2020-12397", "CVE-2020-6831");
  script_xref(name:"IAVA", value:"2020-A-0190-S");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : MozillaThunderbird (SUSE-SU-2020:1225-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaThunderbird fixes the following issues :

Update to 68.8.0 ESR MFSA 2020-18 (bsc#1171186)

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

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12387/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12392/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12393/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12395/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12397/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-6831/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201225-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b7fb363"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15-SP2 :

zypper in -t patch SUSE-SLE-Product-WE-15-SP2-2020-1225=1

SUSE Linux Enterprise Workstation Extension 15-SP1 :

zypper in -t patch SUSE-SLE-Product-WE-15-SP1-2020-1225=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP2-2020-1225=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12395");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "s390x") audit(AUDIT_ARCH_NOT, "s390x", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", cpu:"s390x", reference:"MozillaThunderbird-68.8.0-3.80.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"s390x", reference:"MozillaThunderbird-debuginfo-68.8.0-3.80.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"s390x", reference:"MozillaThunderbird-debugsource-68.8.0-3.80.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"s390x", reference:"MozillaThunderbird-translations-common-68.8.0-3.80.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"s390x", reference:"MozillaThunderbird-translations-other-68.8.0-3.80.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"s390x", reference:"MozillaThunderbird-68.8.0-3.80.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"s390x", reference:"MozillaThunderbird-debuginfo-68.8.0-3.80.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"s390x", reference:"MozillaThunderbird-debugsource-68.8.0-3.80.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"s390x", reference:"MozillaThunderbird-translations-common-68.8.0-3.80.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"s390x", reference:"MozillaThunderbird-translations-other-68.8.0-3.80.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird");
}
