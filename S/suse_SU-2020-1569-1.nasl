#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1569-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(137598);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2020-2754",
    "CVE-2020-2755",
    "CVE-2020-2756",
    "CVE-2020-2757",
    "CVE-2020-2773",
    "CVE-2020-2781",
    "CVE-2020-2800",
    "CVE-2020-2803",
    "CVE-2020-2805",
    "CVE-2020-2830"
  );

  script_name(english:"SUSE SLES15 Security Update : java-1_8_0-openjdk (SUSE-SU-2020:1569-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for java-1_8_0-openjdk to version jdk8u252 fixes the
following issues :

CVE-2020-2754: Forward references to Nashorn (bsc#1169511)

CVE-2020-2755: Improve Nashorn matching (bsc#1169511)

CVE-2020-2756: Better mapping of serial ENUMs (bsc#1169511)

CVE-2020-2757: Less Blocking Array Queues (bsc#1169511)

CVE-2020-2773: Better signatures in XML (bsc#1169511)

CVE-2020-2781: Improve TLS session handling (bsc#1169511)

CVE-2020-2800: Better Headings for HTTP Servers (bsc#1169511)

CVE-2020-2803: Enhance buffering of byte buffers (bsc#1169511)

CVE-2020-2805: Enhance typing of methods (bsc#1169511)

CVE-2020-2830: Better Scanner conversions (bsc#1169511)

Ignore whitespaces after the header or footer in PEM X.509 cert
(bsc#1171352)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1160398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171352");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2754/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2755/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2756/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2757/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2773/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2781/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2800/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2803/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2805/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2830/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201569-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2161ab99");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-1569=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-1569=1

SUSE Linux Enterprise Module for Legacy Software 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Legacy-15-SP1-2020-1569=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2800");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-headless-debuginfo");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-1_8_0-openjdk-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-1_8_0-openjdk-debugsource-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-1_8_0-openjdk-demo-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-1_8_0-openjdk-devel-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-1_8_0-openjdk-headless-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-1_8_0-openjdk-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-1_8_0-openjdk-debugsource-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-1_8_0-openjdk-demo-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-1_8_0-openjdk-devel-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-1_8_0-openjdk-headless-1.8.0.252-3.35.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.252-3.35.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_8_0-openjdk");
}
