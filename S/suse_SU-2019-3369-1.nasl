#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:3369-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(132387);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/27");

  script_cve_id("CVE-2019-2737", "CVE-2019-2739", "CVE-2019-2740", "CVE-2019-2758", "CVE-2019-2805", "CVE-2019-2938", "CVE-2019-2974");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : mariadb (SUSE-SU-2019:3369-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mariadb to version 10.2.29 fixes the following 
issues :

MariaDB was updated to 10.2.29 (bsc#1156669)

Security issues fixed :

CVE-2019-2737: Fixed an issue where could lead a remote attacker to
cause denial of service

CVE-2019-2938: Fixed an issue where could lead a remote attacker to
cause denial of service

CVE-2019-2740: Fixed an issue where could lead a local attacker to
cause denial of service

CVE-2019-2805: Fixed an issue where could lead a local attacker to
cause denial of service

CVE-2019-2974: Fixed an issue where could lead a remote attacker to
cause denial of service

CVE-2019-2758: Fixed an issue where could lead a local attacker to
cause denial of service or data corruption

CVE-2019-2739: Fixed an issue where could lead a local attacker to
cause denial of service or data corruption

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-2737/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-2739/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-2740/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-2758/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-2805/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-2938/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-2974/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20193369-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a1c5f61"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 9:zypper in -t patch
SUSE-OpenStack-Cloud-Crowbar-9-2019-3369=1

SUSE OpenStack Cloud 9:zypper in -t patch
SUSE-OpenStack-Cloud-9-2019-3369=1

SUSE Linux Enterprise Server 12-SP5:zypper in -t patch
SUSE-SLE-SERVER-12-SP5-2019-3369=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-3369=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-3369=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2758");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP4/5", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"mariadb-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mariadb-client-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mariadb-client-debuginfo-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mariadb-debuginfo-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mariadb-debugsource-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mariadb-tools-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mariadb-tools-debuginfo-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"mariadb-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"mariadb-client-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"mariadb-client-debuginfo-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"mariadb-debuginfo-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"mariadb-debugsource-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"mariadb-tools-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"mariadb-tools-debuginfo-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mariadb-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mariadb-client-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mariadb-client-debuginfo-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mariadb-debuginfo-10.2.29-3.22.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mariadb-debugsource-10.2.29-3.22.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb");
}
