#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0496-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(134105);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-18901", "CVE-2020-2574");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : mariadb (SUSE-SU-2020:0496-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for mariadb fixes the following issues :

MariaDB was updated to version 10.2.31 GA (bsc#1162388).

Security issues fixed :

CVE-2020-2574: Fixed a difficult to exploit vulnerability that allowed
an attacker to crash the client (bsc#1162388).

CVE-2019-18901: Fixed an unsafe path handling behavior in
mysql-systemd-helper (bsc#1160895).

Enabled security hardenings in MariaDB's systemd service, namely
ProtectSystem, ProtectHome and UMask (bsc#1160878).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1160878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1160883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1160895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1160912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1162388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-18901/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-2574/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200496-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?369ee724"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Server-Applications-15-SP1-2020-496=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-496=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18901");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqld-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqld19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqld19-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmysqld-devel-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmysqld19-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmysqld19-debuginfo-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-bench-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-bench-debuginfo-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-client-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-client-debuginfo-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-debuginfo-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-debugsource-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-galera-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-test-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-test-debuginfo-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-tools-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-tools-debuginfo-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mariadb-bench-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mariadb-bench-debuginfo-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mariadb-debuginfo-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mariadb-debugsource-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mariadb-galera-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mariadb-test-10.2.31-3.26.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mariadb-test-debuginfo-10.2.31-3.26.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb");
}
