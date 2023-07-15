#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3630-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(143653);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2020-14349",
    "CVE-2020-14350",
    "CVE-2020-25694",
    "CVE-2020-25695",
    "CVE-2020-25696"
  );
  script_xref(name:"IAVB", value:"2020-B-0069-S");

  script_name(english:"SUSE SLES12 Security Update : postgresql12 (SUSE-SU-2020:3630-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for postgresql12 fixes the following issues :

Upgrade to version 12.5 :

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

https://www.postgresql.org/docs/12/release-12-5.html

The previous postgresql12 update already addressed :

Update to 12.4 :

CVE-2020-14349, bsc#1175193: Set a secure search_path in logical
replication walsenders and apply workers

CVE-2020-14350, bsc#1175194: Make contrib modules' installation
scripts more secure.

https://www.postgresql.org/docs/12/release-12-4.html

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1175193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1175194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178668");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/2111/");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/12/release-12-4.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/12/release-12-5.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14349/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14350/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25694/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25695/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25696/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203630-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebb47bf9");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 9 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-9-2020-3630=1

SUSE OpenStack Cloud Crowbar 8 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-8-2020-3630=1

SUSE OpenStack Cloud 9 :

zypper in -t patch SUSE-OpenStack-Cloud-9-2020-3630=1

SUSE OpenStack Cloud 8 :

zypper in -t patch SUSE-OpenStack-Cloud-8-2020-3630=1

SUSE OpenStack Cloud 7 :

zypper in -t patch SUSE-OpenStack-Cloud-7-2020-3630=1

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2020-3630=1

SUSE Linux Enterprise Server for SAP 12-SP4 :

zypper in -t patch SUSE-SLE-SAP-12-SP4-2020-3630=1

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2020-3630=1

SUSE Linux Enterprise Server for SAP 12-SP2 :

zypper in -t patch SUSE-SLE-SAP-12-SP2-2020-3630=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2020-3630=1

SUSE Linux Enterprise Server 12-SP4-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-LTSS-2020-3630=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2020-3630=1

SUSE Linux Enterprise Server 12-SP3-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-BCL-2020-3630=1

SUSE Linux Enterprise Server 12-SP2-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-2020-3630=1

SUSE Linux Enterprise Server 12-SP2-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-BCL-2020-3630=1

SUSE Enterprise Storage 5 :

zypper in -t patch SUSE-Storage-5-2020-3630=1

HPE Helion Openstack 8 :

zypper in -t patch HPE-Helion-OpenStack-8-2020-3630=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25696");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-25695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"libecpg6-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libecpg6-debuginfo-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpq5-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpq5-32bit-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpq5-debuginfo-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpq5-debuginfo-32bit-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libecpg6-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libecpg6-debuginfo-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpq5-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpq5-32bit-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpq5-debuginfo-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpq5-debuginfo-32bit-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libecpg6-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libecpg6-debuginfo-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpq5-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpq5-32bit-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpq5-debuginfo-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpq5-debuginfo-32bit-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libecpg6-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libecpg6-debuginfo-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libpq5-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libpq5-32bit-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libpq5-debuginfo-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libpq5-debuginfo-32bit-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-contrib-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-contrib-debuginfo-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-debuginfo-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-debugsource-12.5-3.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-debugsource-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-plperl-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-plperl-debuginfo-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-plpython-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-plpython-debuginfo-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-pltcl-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-pltcl-debuginfo-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-server-12.5-3.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-server-debuginfo-12.5-3.9.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql12");
}
