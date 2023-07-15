#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3064-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(117992);
  script_version("1.4");
  script_cvs_date("Date: 2019/09/10 13:51:49");

  script_cve_id("CVE-2018-2938", "CVE-2018-2940", "CVE-2018-2952", "CVE-2018-2973", "CVE-2018-3639");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : java-1_8_0-openjdk (SUSE-SU-2018:3064-1) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_8_0-openjdk to the jdk8u181 (icedtea 3.9.0)
release fixes the following issues :

These security issues were fixed :

CVE-2018-2938: Difficult to exploit vulnerability allowed
unauthenticated attacker with network access via multiple protocols to
compromise Java SE. Successful attacks of this vulnerability can
result in takeover of Java SE (bsc#1101644).

CVE-2018-2940: Vulnerability in subcomponent: Libraries. Easily
exploitable vulnerability allowed unauthenticated attacker with
network access via multiple protocols to compromise Java SE, Java SE
Embedded. Successful attacks require human interaction from a person
other than the attacker. Successful attacks of this vulnerability can
result in unauthorized read access to a subset of Java SE, Java SE
Embedded accessible data (bsc#1101645)

CVE-2018-2952: Vulnerability in subcomponent: Concurrency. Difficult
to exploit vulnerability allowed unauthenticated attacker with network
access via multiple protocols to compromise Java SE, Java SE Embedded,
JRockit. Successful attacks of this vulnerability can result in
unauthorized ability to cause a partial denial of service (partial
DOS) of Java SE, Java SE Embedded, JRockit (bsc#1101651)

CVE-2018-2973: Vulnerability in subcomponent: JSSE. Difficult to
exploit vulnerability allowed unauthenticated attacker with network
access via SSL/TLS to compromise Java SE, Java SE Embedded. Successful
attacks of this vulnerability can result in unauthorized creation,
deletion or modification access to critical data or all Java SE, Java
SE Embedded accessible data (bsc#1101656)

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2938/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2940/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2952/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2973/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3639/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183064-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?480f10c8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-2168=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-2168=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-2168=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-2168=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-2168=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-2168=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-2168=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-debugsource-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-demo-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-devel-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-headless-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-debugsource-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-demo-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-devel-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-headless-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-debugsource-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-demo-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-devel-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-headless-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-debugsource-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-1.8.0.181-27.26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.181-27.26.2")) flag++;


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
