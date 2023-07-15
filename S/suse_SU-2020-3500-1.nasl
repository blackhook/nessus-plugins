#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3500-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(143796);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2020-14765",
    "CVE-2020-14776",
    "CVE-2020-14789",
    "CVE-2020-14812",
    "CVE-2020-15180"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : mariadb (SUSE-SU-2020:3500-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for mariadb and mariadb-connector-c fixes the following
issues :

Update mariadb to 10.2.36 GA [bsc#1177472, bsc#1178428] fixing for the
following security vulnerabilities: CVE-2020-14812, CVE-2020-14765,
CVE-2020-14776, CVE-2020-14789 CVE-2020-15180

Update mariadb-connector-c to 3.1.11 [bsc#1177472 and bsc#1178428]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1175596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178428");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14765/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14776/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14789/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14812/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15180/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203500-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d6ab935");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-3500=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-3500=1

SUSE Linux Enterprise Module for Server Applications 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Server-Applications-15-SP2-2020-3500=1

SUSE Linux Enterprise Module for Server Applications 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Server-Applications-15-SP1-2020-3500=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2020-3500=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-3500=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-3500=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-3500=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15180");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmariadb-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmariadb3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmariadb3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmariadb_plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmariadb_plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmariadbprivate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmariadbprivate-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqld-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqld19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqld19-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-connector-c-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmariadb-devel-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmariadb-devel-debuginfo-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmariadb3-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmariadb3-debuginfo-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmariadb_plugins-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmariadb_plugins-debuginfo-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmariadbprivate-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmariadbprivate-debuginfo-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmysqld-devel-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmysqld19-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmysqld19-debuginfo-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-client-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-client-debuginfo-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-connector-c-debugsource-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-debuginfo-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-debugsource-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-tools-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mariadb-tools-debuginfo-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libmariadb-devel-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libmariadb-devel-debuginfo-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libmariadb3-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libmariadb3-debuginfo-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libmariadb_plugins-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libmariadb_plugins-debuginfo-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libmariadbprivate-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libmariadbprivate-debuginfo-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libmysqld-devel-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libmysqld19-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libmysqld19-debuginfo-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"mariadb-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"mariadb-client-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"mariadb-client-debuginfo-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"mariadb-connector-c-debugsource-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"mariadb-debuginfo-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"mariadb-debugsource-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"mariadb-tools-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"mariadb-tools-debuginfo-10.2.36-3.34.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libmariadb-devel-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libmariadb-devel-debuginfo-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libmariadb3-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libmariadb3-debuginfo-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libmariadb_plugins-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libmariadb_plugins-debuginfo-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libmariadbprivate-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libmariadbprivate-debuginfo-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"mariadb-connector-c-debugsource-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libmariadb3-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libmariadb3-debuginfo-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libmariadbprivate-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libmariadbprivate-debuginfo-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mariadb-connector-c-debugsource-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libmariadb3-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libmariadb3-debuginfo-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libmariadbprivate-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libmariadbprivate-debuginfo-3.1.11-3.22.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"mariadb-connector-c-debugsource-3.1.11-3.22.2")) flag++;


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
