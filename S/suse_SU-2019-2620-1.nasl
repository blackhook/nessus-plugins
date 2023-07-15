#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2620-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(129772);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-9811",
    "CVE-2019-9812",
    "CVE-2019-11709",
    "CVE-2019-11710",
    "CVE-2019-11711",
    "CVE-2019-11712",
    "CVE-2019-11713",
    "CVE-2019-11714",
    "CVE-2019-11715",
    "CVE-2019-11716",
    "CVE-2019-11717",
    "CVE-2019-11718",
    "CVE-2019-11719",
    "CVE-2019-11720",
    "CVE-2019-11721",
    "CVE-2019-11723",
    "CVE-2019-11724",
    "CVE-2019-11725",
    "CVE-2019-11727",
    "CVE-2019-11728",
    "CVE-2019-11729",
    "CVE-2019-11730",
    "CVE-2019-11733",
    "CVE-2019-11735",
    "CVE-2019-11736",
    "CVE-2019-11738",
    "CVE-2019-11740",
    "CVE-2019-11742",
    "CVE-2019-11743",
    "CVE-2019-11744",
    "CVE-2019-11746",
    "CVE-2019-11747",
    "CVE-2019-11748",
    "CVE-2019-11749",
    "CVE-2019-11750",
    "CVE-2019-11751",
    "CVE-2019-11752",
    "CVE-2019-11753"
  );

  script_name(english:"SUSE SLED12 / SLES12 Security Update : MozillaFirefox (SUSE-SU-2019:2620-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for MozillaFirefox fixes the following issues :

Updated to new ESR version 68.1 (bsc#1149323).

In addition to the already fixed vulnerabilities released in previous
ESR updates, the following were also fixed: CVE-2019-11751,
CVE-2019-11736, CVE-2019-9812, CVE-2019-11748, CVE-2019-11749,
CVE-2019-11750, CVE-2019-11738, CVE-2019-11747, CVE-2019-11735.

Several run-time issues were also resolved (bsc#1117473, bsc#1124525,
bsc#1133810).

The version displayed in Help > About is now correct (bsc#1087200).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1087200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1109465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1117473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1123482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1124525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1133810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1140868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1145665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149323");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11709/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11710/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11711/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11712/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11713/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11714/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11715/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11716/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11717/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11718/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11719/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11720/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11721/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11723/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11724/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11725/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11727/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11728/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11729/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11730/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11733/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11735/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11736/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11738/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11740/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11742/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11743/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11744/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11746/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11747/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11748/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11749/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11750/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11751/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11752/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11753/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9811/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9812/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192620-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?baf78245");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8:zypper in -t patch
SUSE-OpenStack-Cloud-Crowbar-8-2019-2620=1

SUSE OpenStack Cloud 8:zypper in -t patch
SUSE-OpenStack-Cloud-8-2019-2620=1

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2019-2620=1

SUSE Linux Enterprise Software Development Kit 12-SP5:zypper in -t
patch SUSE-SLE-SDK-12-SP5-2019-2620=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-2620=1

SUSE Linux Enterprise Server for SAP 12-SP3:zypper in -t patch
SUSE-SLE-SAP-12-SP3-2019-2620=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2019-2620=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2019-2620=1

SUSE Linux Enterprise Server 12-SP5:zypper in -t patch
SUSE-SLE-SERVER-12-SP5-2019-2620=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-2620=1

SUSE Linux Enterprise Server 12-SP3-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-2620=1

SUSE Linux Enterprise Server 12-SP3-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-BCL-2019-2620=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2019-2620=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2019-2620=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2019-2620=1

SUSE Linux Enterprise Desktop 12-SP5:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP5-2019-2620=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-2620=1

SUSE Enterprise Storage 5:zypper in -t patch
SUSE-Storage-5-2019-2620=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2019-2620=1

HPE Helion Openstack 8:zypper in -t patch
HPE-Helion-OpenStack-8-2019-2620=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11752");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-11733");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES12" && (! preg(pattern:"^(1|2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2/3/4/5", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-branding-SLE-68-32.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-debuginfo-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-debugsource-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-devel-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-translations-common-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"MozillaFirefox-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"MozillaFirefox-branding-SLE-68-32.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"MozillaFirefox-debuginfo-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"MozillaFirefox-debugsource-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"MozillaFirefox-translations-common-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-branding-SLE-68-32.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-debuginfo-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-debugsource-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-translations-common-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-branding-SLE-68-32.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-debuginfo-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-debugsource-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-devel-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-translations-common-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"MozillaFirefox-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"MozillaFirefox-branding-SLE-68-32.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"MozillaFirefox-debuginfo-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"MozillaFirefox-debugsource-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"MozillaFirefox-translations-common-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-branding-SLE-68-32.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-debugsource-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-translations-common-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"MozillaFirefox-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"MozillaFirefox-branding-SLE-68-32.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"MozillaFirefox-debugsource-68.1.0-109.89.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"MozillaFirefox-translations-common-68.1.0-109.89.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
