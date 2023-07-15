#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1695-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(110548);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-1115");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : postgresql96 (SUSE-SU-2018:1695-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"PostgreSQL was updated to 9.6.9 fixing bugs and security issues:
Release notes :

- https://www.postgresql.org/about/news/1851/

- https://www.postgresql.org/docs/current/static/release-9-6-9.html
A dump/restore is not required for those running 9.6.X. However, if you
use the adminpack extension, you should update it as per the first
changelog entry below. Also, if the function marking mistakes mentioned in
the second and third changelog entries below affect you, you will want to
take steps to correct your database catalogs.
Security issue fixed :

  - CVE-2018-1115: Remove public execute privilege from
    contrib/adminpack's pg_logfile_rotate() function
    pg_logfile_rotate() is a deprecated wrapper for the core
    function pg_rotate_logfile(). When that function was
    changed to rely on SQL privileges for access control
    rather than a hard-coded superuser check,
    pg_logfile_rotate() should have been updated as well,
    but the need for this was missed. Hence, if adminpack is
    installed, any user could request a logfile rotation,
    creating a minor security issue. After installing this
    update, administrators should update adminpack by
    performing ALTER EXTENSION adminpack UPDATE in each
    database in which adminpack is installed. (bsc#1091610)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/about/news/1851/"
  );
  # https://www.postgresql.org/docs/current/static/release-9-6-9.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/current/release-9-6-9.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1115/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181695-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3df3eceb"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-1138=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-1138=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-1138=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-libs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"libecpg6-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libecpg6-debuginfo-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpq5-32bit-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpq5-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpq5-debuginfo-32bit-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpq5-debuginfo-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-contrib-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-contrib-debuginfo-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-debuginfo-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-debugsource-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-libs-debugsource-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-server-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-server-debuginfo-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libecpg6-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libecpg6-debuginfo-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libpq5-32bit-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libpq5-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libpq5-debuginfo-32bit-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libpq5-debuginfo-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"postgresql96-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"postgresql96-debuginfo-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"postgresql96-debugsource-9.6.9-3.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"postgresql96-libs-debugsource-9.6.9-3.19.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql96");
}
