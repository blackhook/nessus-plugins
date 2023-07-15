#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2192-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119972);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2015-0204",
    "CVE-2015-0458",
    "CVE-2015-0459",
    "CVE-2015-0469",
    "CVE-2015-0477",
    "CVE-2015-0478",
    "CVE-2015-0480",
    "CVE-2015-0488",
    "CVE-2015-0491",
    "CVE-2015-2625",
    "CVE-2015-2808",
    "CVE-2015-4734",
    "CVE-2015-4803",
    "CVE-2015-4805",
    "CVE-2015-4806",
    "CVE-2015-4810",
    "CVE-2015-4835",
    "CVE-2015-4840",
    "CVE-2015-4842",
    "CVE-2015-4843",
    "CVE-2015-4844",
    "CVE-2015-4860",
    "CVE-2015-4871",
    "CVE-2015-4872",
    "CVE-2015-4882",
    "CVE-2015-4883",
    "CVE-2015-4893",
    "CVE-2015-4902",
    "CVE-2015-4903",
    "CVE-2015-4911",
    "CVE-2015-5006"
  );
  script_bugtraq_id(
    71936,
    73684,
    74072,
    74083,
    74094,
    74104,
    74111,
    74119,
    74141,
    74147,
    75895
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"SUSE SLES12 Security Update : java-1_6_0-ibm (SUSE-SU-2015:2192-1) (Bar Mitzvah) (FREAK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for java-1_6_0-ibm fixes the following issues :

  - Version update to 6.0-16.15 bsc#955131: CVE-2015-4734
    CVE-2015-4803 CVE-2015-4805 CVE-2015-4806 CVE-2015-4810
    CVE-2015-4835 CVE-2015-4840 CVE-2015-4842 CVE-2015-4843
    CVE-2015-4844 CVE-2015-4860 CVE-2015-4871 CVE-2015-4872
    CVE-2015-4882 CVE-2015-4883 CVE-2015-4893 CVE-2015-4902
    CVE-2015-4903 CVE-2015-4911 CVE-2015-5006 CVE-2015-2808
    CVE-2015-2625 CVE-2015-0491 CVE-2015-0459 CVE-2015-0469
    CVE-2015-0458 CVE-2015-0480 CVE-2015-0488 CVE-2015-0478
    CVE-2015-0477 CVE-2015-0204

  - Add backcompat symlinks for sdkdir

  - Fix baselibs.conf policy symlinking

  - Fix bsc#941939 to provide %{name} instead of %{sdklnk}
    only in _jvmprivdir

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=941939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=955131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-0204/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-0458/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-0459/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-0469/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-0477/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-0478/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-0480/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-0488/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-0491/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2625/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2808/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4734/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4803/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4805/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4806/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4810/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4835/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4840/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4842/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4843/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4844/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4860/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4871/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4872/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4882/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4883/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4893/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4902/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4903/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4911/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-5006/");
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152192-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5766730");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Legacy Software 12 :

zypper in -t patch SUSE-SLE-Module-Legacy-12-2015-943=1

To bring your system up-to-date, use 'zypper patch'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4883");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_6_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_6_0-ibm-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_6_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_6_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"java-1_6_0-ibm-plugin-1.6.0_sr16.15-27.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_6_0-ibm-1.6.0_sr16.15-27.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_6_0-ibm-fonts-1.6.0_sr16.15-27.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_6_0-ibm-jdbc-1.6.0_sr16.15-27.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_6_0-ibm");
}
