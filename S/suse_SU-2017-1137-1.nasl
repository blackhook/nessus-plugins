#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1137-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99760);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-5483", "CVE-2017-3302", "CVE-2017-3305", "CVE-2017-3308", "CVE-2017-3309", "CVE-2017-3329", "CVE-2017-3453", "CVE-2017-3456", "CVE-2017-3461", "CVE-2017-3462", "CVE-2017-3463", "CVE-2017-3464", "CVE-2017-3600");

  script_name(english:"SUSE SLES11 Security Update : mysql (SUSE-SU-2017:1137-1) (Riddle)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mysql to version 5.5.55 fixes the following issues:
These security issues were fixed :

  - CVE-2017-3308: Unspecified vulnerability in Server: DML
    (bsc#1034850)

  - CVE-2017-3309: Unspecified vulnerability in Server:
    Optimizer (bsc#1034850)

  - CVE-2017-3329: Unspecified vulnerability in Server:
    Thread (bsc#1034850)

  - CVE-2017-3600: Unspecified vulnerability in Client:
    mysqldump (bsc#1034850)

  - CVE-2017-3453: Unspecified vulnerability in Server:
    Optimizer (bsc#1034850)

  - CVE-2017-3456: Unspecified vulnerability in Server: DML
    (bsc#1034850)

  - CVE-2017-3463: Unspecified vulnerability in Server:
    Security (bsc#1034850)

  - CVE-2017-3462: Unspecified vulnerability in Server:
    Security (bsc#1034850)

  - CVE-2017-3461: Unspecified vulnerability in Server:
    Security (bsc#1034850)

  - CVE-2017-3464: Unspecified vulnerability in Server: DDL
    (bsc#1034850)

  - CVE-2017-3305: MySQL client sent authentication request
    unencrypted even if SSL was required (aka Ridddle)
    (bsc#1029396).

  - CVE-2016-5483: Mysqldump failed to properly quote
    certain identifiers in SQL statements written to the
    dump output, allowing for execution of arbitrary
    commands (bsc#1029014)

  - '--ssl-mode=REQUIRED' can be specified to require a
    secure connection (it fails if a secure connection
    cannot be obtained)

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1020976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1022428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1034850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5483/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3302/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3305/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3308/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3309/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3329/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3453/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3456/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3461/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3462/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3463/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3464/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3600/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171137-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65a99eb7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-mysql-13081=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-mysql-13081=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-mysql-13081=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysql55client18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysql55client_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.55-0.38.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libmysql55client_r18-32bit-5.5.55-0.38.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libmysql55client18-32bit-5.5.55-0.38.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libmysql55client_r18-32bit-5.5.55-0.38.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libmysql55client18-5.5.55-0.38.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libmysql55client_r18-5.5.55-0.38.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-5.5.55-0.38.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-client-5.5.55-0.38.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-tools-5.5.55-0.38.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql");
}
