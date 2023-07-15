#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0466-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(134080);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-4732",
    "CVE-2020-2583",
    "CVE-2020-2593",
    "CVE-2020-2604",
    "CVE-2020-2659"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : java-1_8_0-ibm (SUSE-SU-2020:0466-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for java-1_8_0-ibm fixes the following issues :

Java 8.0 was updated to Service Refresh 6 Fix Pack 5 (bsc#1162972,
bsc#1160968)

CVE-2020-2583: Unlink Set of LinkedHashSets

CVE-2019-4732: Untrusted DLL search path vulnerability

CVE-2020-2593: Normalize normalization for all

CVE-2020-2604: Better serial filter handling

CVE-2020-2659: Enhance datagram socket support

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1160968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-4732/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2583/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2593/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2604/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2659/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200466-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73841e79");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15:zypper in -t patch
SUSE-SLE-Product-SLES_SAP-15-2020-466=1

SUSE Linux Enterprise Server 15-LTSS:zypper in -t patch
SUSE-SLE-Product-SLES-15-2020-466=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-466=1

SUSE Linux Enterprise Module for Legacy Software 15-SP1:zypper in -t
patch SUSE-SLE-Module-Legacy-15-SP1-2020-466=1

SUSE Linux Enterprise Module for Legacy Software 15:zypper in -t patch
SUSE-SLE-Module-Legacy-15-2020-466=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-4732");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-src");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"java-1_8_0-ibm-32bit-1.8.0_sr6.5-3.33.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"java-1_8_0-ibm-alsa-1.8.0_sr6.5-3.33.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"java-1_8_0-ibm-devel-32bit-1.8.0_sr6.5-3.33.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"java-1_8_0-ibm-plugin-1.8.0_sr6.5-3.33.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-1_8_0-ibm-1.8.0_sr6.5-3.33.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-1_8_0-ibm-demo-1.8.0_sr6.5-3.33.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-1_8_0-ibm-devel-1.8.0_sr6.5-3.33.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-1_8_0-ibm-src-1.8.0_sr6.5-3.33.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"java-1_8_0-ibm-alsa-1.8.0_sr6.5-3.33.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"java-1_8_0-ibm-plugin-1.8.0_sr6.5-3.33.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"java-1_8_0-ibm-1.8.0_sr6.5-3.33.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"java-1_8_0-ibm-devel-1.8.0_sr6.5-3.33.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"java-1_8_0-ibm-32bit-1.8.0_sr6.5-3.33.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"java-1_8_0-ibm-devel-32bit-1.8.0_sr6.5-3.33.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"java-1_8_0-ibm-demo-1.8.0_sr6.5-3.33.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"java-1_8_0-ibm-src-1.8.0_sr6.5-3.33.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_8_0-ibm");
}
