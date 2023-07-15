#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3065-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(143696);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-12861", "CVE-2020-12862", "CVE-2020-12863", "CVE-2020-12864", "CVE-2020-12865", "CVE-2020-12866", "CVE-2020-12867");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : sane-backends (SUSE-SU-2020:3065-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for sane-backends fixes the following issues :

sane-backends was updated to 1.0.31 to further improve hardware
enablement for scanner devices (jsc#ECO-2418 jsc#SLE-15561
jsc#SLE-15560) and also fix various security issues :

CVE-2020-12861,CVE-2020-12865: Fixed an out of bounds write
(bsc#1172524)

CVE-2020-12862,CVE-2020-12863,CVE-2020-12864,: Fixed an out of bounds
read (bsc#1172524)

CVE-2020-12866,CVE-2020-12867: Fixed a NULL pointer dereference
(bsc#1172524)

The upstream changelogs can be found here :

https://gitlab.com/sane-project/backends/-/releases/1.0.28

https://gitlab.com/sane-project/backends/-/releases/1.0.29

https://gitlab.com/sane-project/backends/-/releases/1.0.30

https://gitlab.com/sane-project/backends/-/releases/1.0.31

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://gitlab.com/sane-project/backends/-/releases/1.0.28"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://gitlab.com/sane-project/backends/-/releases/1.0.29"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://gitlab.com/sane-project/backends/-/releases/1.0.30"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://gitlab.com/sane-project/backends/-/releases/1.0.31"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12861/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12862/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12863/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12864/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12865/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12866/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12867/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203065-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8136cbd8"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Packagehub-Subpackages-15-SP2-2020-3065=1

SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Packagehub-Subpackages-15-SP1-2020-3065=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Desktop-Applications-15-SP2-2020-3065=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Desktop-Applications-15-SP1-2020-3065=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sane-backends");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sane-backends-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sane-backends-autoconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sane-backends-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sane-backends-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sane-backends-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1/2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"sane-backends-32bit-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"sane-backends-32bit-debuginfo-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sane-backends-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sane-backends-autoconfig-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sane-backends-debuginfo-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sane-backends-debugsource-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sane-backends-devel-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"sane-backends-32bit-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"sane-backends-32bit-debuginfo-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"sane-backends-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"sane-backends-autoconfig-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"sane-backends-debuginfo-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"sane-backends-debugsource-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"sane-backends-devel-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"sane-backends-32bit-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"sane-backends-32bit-debuginfo-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sane-backends-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sane-backends-autoconfig-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sane-backends-debuginfo-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sane-backends-debugsource-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sane-backends-devel-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"sane-backends-32bit-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"sane-backends-32bit-debuginfo-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"sane-backends-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"sane-backends-autoconfig-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"sane-backends-debuginfo-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"sane-backends-debugsource-1.0.31-6.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"sane-backends-devel-1.0.31-6.3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sane-backends");
}
