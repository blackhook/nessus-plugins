#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2989-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104531);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2016-10165", "CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843", "CVE-2017-10274", "CVE-2017-10281", "CVE-2017-10285", "CVE-2017-10295", "CVE-2017-10345", "CVE-2017-10346", "CVE-2017-10347", "CVE-2017-10348", "CVE-2017-10349", "CVE-2017-10350", "CVE-2017-10355", "CVE-2017-10356", "CVE-2017-10357", "CVE-2017-10388");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : java-1_8_0-openjdk (SUSE-SU-2017:2989-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_8_0-openjdk fixes the following issues :

  - Update to version jdk8u151 (icedtea 3.6.0) Security
    issues fixed :

  - CVE-2017-10274: Handle smartcard clean up better
    (bsc#1064071)

  - CVE-2017-10281: Better queuing priorities (bsc#1064072)

  - CVE-2017-10285: Unreferenced references (bsc#1064073)

  - CVE-2017-10295: Better URL connections (bsc#1064075)

  - CVE-2017-10388: Correct Kerberos ticket grants
    (bsc#1064086)

  - CVE-2017-10346: Better invokespecial checks
    (bsc#1064078)

  - CVE-2017-10350: Better Base Exceptions (bsc#1064082)

  - CVE-2017-10347: Better timezone processing (bsc#1064079)

  - CVE-2017-10349: Better X processing (bsc#1064081)

  - CVE-2017-10345: Better keystore handling (bsc#1064077)

  - CVE-2017-10348: Better processing of unresolved
    permissions (bsc#1064080)

  - CVE-2017-10357: Process Proxy presentation (bsc#1064085)

  - CVE-2017-10355: More stable connection processing
    (bsc#1064083)

  - CVE-2017-10356: Update storage implementations
    (bsc#1064084)

  - CVE-2016-10165: Improve CMS header processing
    (bsc#1064069)

  - CVE-2016-9840, CVE-2016-9841, CVE-2016-9842,
    CVE-2016-9843: Upgrade compression library (bsc#1064070)
    Bug fixes :

  - Fix bsc#1032647, bsc#1052009 with btrfs subvolumes and
    overlayfs

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1032647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10165/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9840/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9841/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9842/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9843/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10274/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10281/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10285/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10295/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10345/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10346/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10347/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10348/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10349/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10350/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10355/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10356/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10357/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10388/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172989-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b56d4a6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 6:zypper in -t patch
SUSE-OpenStack-Cloud-6-2017-1847=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2017-1847=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1847=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2017-1847=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1847=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-1847=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-1847=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1847=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/13");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-debugsource-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-demo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-devel-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-headless-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-debugsource-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-demo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-devel-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-headless-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-debugsource-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-demo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-devel-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-headless-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-debugsource-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-debugsource-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-1.8.0.151-27.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.151-27.8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_8_0-openjdk");
}
