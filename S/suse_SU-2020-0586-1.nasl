#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0586-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(134295);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-1720");

  script_name(english:"SUSE SLES12 Security Update : postgresql96 (SUSE-SU-2020:0586-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for postgresql96 fixes the following issues :

PostgreSQL was updated to version 9.6.17.

Security issue fixed :

CVE-2020-1720: Fixed a missing authorization check in the ALTER ...
DEPENDS ON extension (bsc#1163985).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1163985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-1720/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200586-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4733830"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8:zypper in -t patch
SUSE-OpenStack-Cloud-Crowbar-8-2020-586=1

SUSE OpenStack Cloud 8:zypper in -t patch
SUSE-OpenStack-Cloud-8-2020-586=1

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2020-586=1

SUSE Linux Enterprise Server for SAP 12-SP3:zypper in -t patch
SUSE-SLE-SAP-12-SP3-2020-586=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2020-586=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2020-586=1

SUSE Linux Enterprise Server 12-SP3-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2020-586=1

SUSE Linux Enterprise Server 12-SP3-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-BCL-2020-586=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2020-586=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2020-586=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2020-586=1

SUSE Enterprise Storage 5:zypper in -t patch SUSE-Storage-5-2020-586=1

HPE Helion Openstack 8:zypper in -t patch
HPE-Helion-OpenStack-8-2020-586=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1720");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-libs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"postgresql96-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"postgresql96-contrib-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"postgresql96-contrib-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"postgresql96-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"postgresql96-debugsource-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"postgresql96-libs-debugsource-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"postgresql96-plperl-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"postgresql96-plperl-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"postgresql96-plpython-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"postgresql96-plpython-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"postgresql96-pltcl-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"postgresql96-pltcl-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"postgresql96-server-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"postgresql96-server-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-contrib-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-contrib-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-debugsource-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-libs-debugsource-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-plperl-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-plperl-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-plpython-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-plpython-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-pltcl-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-pltcl-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-server-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-server-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-contrib-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-contrib-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-debugsource-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-libs-debugsource-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-plperl-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-plperl-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-plpython-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-plpython-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-pltcl-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-pltcl-debuginfo-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-server-9.6.17-3.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-server-debuginfo-9.6.17-3.33.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql96");
}
