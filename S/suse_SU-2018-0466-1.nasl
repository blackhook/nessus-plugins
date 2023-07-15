#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0466-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(106899);
  script_version("3.4");
  script_cvs_date("Date: 2019/09/10 13:51:47");

  script_cve_id("CVE-2017-15132");

  script_name(english:"SUSE SLES12 Security Update : dovecot22 (SUSE-SU-2018:0466-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dovecot22 fixes one issue. This security issue was
fixed :

  - CVE-2017-15132: An abort of SASL authentication resulted
    in a memory leak in dovecot's auth client used by login
    processes. The leak has impact in high performance
    configuration where same login processes are reused and
    can cause the process to crash due to memory exhaustion
    (bsc#1075608).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15132/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180466-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54800102"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-321=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2018-321=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2018-321=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-321=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-321=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot22-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot22-backend-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot22-backend-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot22-backend-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot22-backend-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot22-backend-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot22-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot22-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"dovecot22-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"dovecot22-backend-mysql-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"dovecot22-backend-mysql-debuginfo-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"dovecot22-backend-pgsql-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"dovecot22-backend-pgsql-debuginfo-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"dovecot22-backend-sqlite-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"dovecot22-backend-sqlite-debuginfo-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"dovecot22-debuginfo-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"dovecot22-debugsource-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"dovecot22-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"dovecot22-backend-mysql-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"dovecot22-backend-mysql-debuginfo-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"dovecot22-backend-pgsql-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"dovecot22-backend-pgsql-debuginfo-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"dovecot22-backend-sqlite-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"dovecot22-backend-sqlite-debuginfo-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"dovecot22-debuginfo-2.2.31-19.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"dovecot22-debugsource-2.2.31-19.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot22");
}
