#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1798-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(138309);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-2752", "CVE-2020-2812");

  script_name(english:"SUSE SLES12 Security Update : mariadb-100 (SUSE-SU-2020:1798-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for mariadb-100 fixes the following issues :

mariadb-100 was updated to version 10.0.44 (bsc#1171550)

CVE-2020-2752: Fixed an issue which could have resulted in
unauthorized ability to cause denial of service.

CVE-2020-2812: Fixed an issue which could have resulted in
unauthorized ability to cause denial of service.

Fixed some test failures

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171550");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2752/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2812/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201798-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a246fb8");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP5 :

zypper in -t patch SUSE-SLE-WE-12-SP5-2020-1798=1

SUSE Linux Enterprise Workstation Extension 12-SP4 :

zypper in -t patch SUSE-SLE-WE-12-SP4-2020-1798=1

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2020-1798=1

SUSE Linux Enterprise Software Development Kit 12-SP4 :

zypper in -t patch SUSE-SLE-SDK-12-SP4-2020-1798=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2020-1798=1

SUSE Linux Enterprise Server 12-SP4 :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-2020-1798=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2812");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2752");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-100-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-100-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-100-errormessages");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"libmysqlclient18-10.0.40.4-2.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libmysqlclient18-32bit-10.0.40.4-2.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libmysqlclient18-debuginfo-10.0.40.4-2.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libmysqlclient18-debuginfo-32bit-10.0.40.4-2.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mariadb-100-debuginfo-10.0.40.4-2.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mariadb-100-debugsource-10.0.40.4-2.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mariadb-100-errormessages-10.0.40.4-2.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libmysqlclient18-10.0.40.4-2.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libmysqlclient18-32bit-10.0.40.4-2.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libmysqlclient18-debuginfo-10.0.40.4-2.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libmysqlclient18-debuginfo-32bit-10.0.40.4-2.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"mariadb-100-debuginfo-10.0.40.4-2.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"mariadb-100-debugsource-10.0.40.4-2.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"mariadb-100-errormessages-10.0.40.4-2.20.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb-100");
}
