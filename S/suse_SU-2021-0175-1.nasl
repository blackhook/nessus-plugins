#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0175-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(145239);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id("CVE-2020-25694", "CVE-2020-25695", "CVE-2020-25696");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : postgresql, postgresql13 (SUSE-SU-2021:0175-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for postgresql, postgresql13 fixes the following issues :

This update ships postgresql13.

Upgrade to version 13.1 :

CVE-2020-25695, bsc#1178666: Block DECLARE CURSOR ... WITH HOLD and
firing of deferred triggers within index expressions and materialized
view queries.

CVE-2020-25694, bsc#1178667: a) Fix usage of complex connection-string
parameters in pg_dump, pg_restore, clusterdb, reindexdb, and vacuumdb.
b) When psql's \connect command re-uses connection parameters, ensure
that all non-overridden parameters from a previous connection string
are re-used.

CVE-2020-25696, bsc#1178668: Prevent psql's \gset command from
modifying specially-treated variables.

Fix recently-added timetz test case so it works when the USA is not
observing daylight savings time. (obsoletes postgresql-timetz.patch)

https://www.postgresql.org/about/news/2111/

https://www.postgresql.org/docs/13/release-13-1.html

Initial packaging of PostgreSQL 13 :

https://www.postgresql.org/about/news/2077/

https://www.postgresql.org/docs/13/release-13.html

bsc#1178961: %ghost the symlinks to pg_config and ecpg.

Changes in postgresql wrapper package :

Bump major version to 13.

We also transfer PostgreSQL 9.4.26 to the new package layout in
SLE12-SP2 and newer. Reflect this in the conflict with postgresql94.

Also conflict with PostgreSQL versions before 9.

Conflicting with older versions is not limited to SLE.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178961");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/2077/");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/2111/");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/13/release-13-1.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/13/release-13.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25694/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25695/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25696/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210175-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7248f14");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Server-Applications-15-SP2-2021-175=1

SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Packagehub-Subpackages-15-SP2-2021-175=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-175=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25696");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-25695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-server-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql13-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libpq5-32bit-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libpq5-32bit-debuginfo-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libecpg6-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libecpg6-debuginfo-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libpq5-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libpq5-debuginfo-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-contrib-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-contrib-debuginfo-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-debuginfo-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-debugsource-13.1-5.3.10")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-debugsource-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-devel-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-devel-debuginfo-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-plperl-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-plperl-debuginfo-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-plpython-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-plpython-debuginfo-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-pltcl-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-pltcl-debuginfo-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-server-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-server-debuginfo-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-server-devel-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-server-devel-debuginfo-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"postgresql13-test-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libpq5-32bit-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libpq5-32bit-debuginfo-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libpq5-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libpq5-debuginfo-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"postgresql13-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"postgresql13-debuginfo-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"postgresql13-debugsource-13.1-5.3.10")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"postgresql13-debugsource-13.1-5.3.15")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"postgresql13-test-13.1-5.3.15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql13");
}
