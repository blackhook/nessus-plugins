#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3436-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(118454);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/02");

  script_cve_id("CVE-2018-14680", "CVE-2018-14681", "CVE-2018-14682", "CVE-2018-15378");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : clamav (SUSE-SU-2018:3436-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for clamav fixes the following issues :

clamav was updated to version 0.100.2 :

CVE-2018-15378: Vulnerability in ClamAV's MEW unpacking feature that
could allow an unauthenticated, remote attacker to cause a denial of
service (DoS) condition on an affected device. (bsc#1110723)

CVE-2018-14680, CVE-2018-14681, CVE-2018-14682: more fixes for
embedded libmspack. (bsc#1103040)

Make freshclam more robust against lagging signature mirrors.

On-Access 'Extra Scanning', an opt-in minor feature of OnAccess
scanning on Linux systems, has been disabled due to a known issue with
resource cleanup OnAccessExtraScanning will be re-enabled in a future
release when the issue is resolved. In the mean-time, users who
enabled the feature in clamd.conf will see a warning informing them
that the feature is not active. For details, see:
https://bugzilla.clamav.net/show_bug.cgi?id=12048

Restore exit code compatibility of freshclam with versions before
0.100.0 when the virus database is already up to date (bsc#1104457).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.clamav.net/show_bug.cgi?id=12048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1110723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14680/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14681/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14682/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15378/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183436-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30dca6b7"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-2460=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-2460=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-2460=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-2460=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2018-2460=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-2460=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-2460=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-2460=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-2460=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14682");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:clamav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:clamav-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"clamav-0.100.2-33.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"clamav-debuginfo-0.100.2-33.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"clamav-debugsource-0.100.2-33.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"clamav-0.100.2-33.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"clamav-debuginfo-0.100.2-33.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"clamav-debugsource-0.100.2-33.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"clamav-0.100.2-33.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"clamav-debuginfo-0.100.2-33.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"clamav-debugsource-0.100.2-33.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"clamav-0.100.2-33.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"clamav-debuginfo-0.100.2-33.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"clamav-debugsource-0.100.2-33.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"clamav-0.100.2-33.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"clamav-debuginfo-0.100.2-33.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"clamav-debugsource-0.100.2-33.18.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav");
}
