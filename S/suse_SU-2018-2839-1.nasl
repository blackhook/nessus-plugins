#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2839-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(117700);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/25");

  script_cve_id("CVE-2016-0705", "CVE-2017-3732", "CVE-2017-3736", "CVE-2018-12539", "CVE-2018-1517", "CVE-2018-1656", "CVE-2018-2940", "CVE-2018-2952", "CVE-2018-2964", "CVE-2018-2973");

  script_name(english:"SUSE SLES12 Security Update : java-1_8_0-ibm (SUSE-SU-2018:2839-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for java-1_8_0-ibm to 8.0.5.20 fixes the following
security issues :

CVE-2018-2952: Vulnerability in subcomponent: Concurrency. Difficult
to exploit vulnerability allowed unauthenticated attacker with network
access via multiple protocols to compromise Java SE, Java SE Embedded,
JRockit. Successful attacks of this vulnerability can result in
unauthorized ability to cause a partial denial of service (partial
DOS) of Java SE, Java SE Embedded, JRockit (bsc#1104668)

CVE-2018-2940: Vulnerability in subcomponent: Libraries. Easily
exploitable vulnerability allowed unauthenticated attacker with
network access via multiple protocols to compromise Java SE, Java SE
Embedded. Successful attacks require human interaction from a person
other than the attacker. Successful attacks of this vulnerability can
result in unauthorized read access to a subset of Java SE, Java SE
Embedded accessible data (bsc#1104668)

CVE-2018-2973: Vulnerability in subcomponent: JSSE. Difficult to
exploit vulnerability allowed unauthenticated attacker with network
access via SSL/TLS to compromise Java SE, Java SE Embedded. Successful
attacks of this vulnerability can result in unauthorized creation,
deletion or modification access to critical data or all Java SE, Java
SE Embedded accessible data (bsc#1104668)

CVE-2018-2964: Vulnerability in subcomponent: Deployment. Difficult to
exploit vulnerability allowed unauthenticated attacker with network
access via multiple protocols to compromise Java SE. Successful
attacks require human interaction from a person other than the
attacker. Successful attacks of this vulnerability can result in
takeover of Java SE. (bsc#1104668)

CVE-2016-0705: Prevent double free in the dsa_priv_decode function
that allowed remote attackers to cause a denial of service (memory
corruption) or possibly have unspecified other impact via a malformed
DSA private key (bsc#1104668)

CVE-2017-3732: Prevent carry propagating bug in the x86_64 Montgomery
squaring procedure (bsc#1104668)

CVE-2017-3736: Prevent carry propagating bug in the x86_64 Montgomery
squaring procedure (bsc#1104668)

CVE-2018-1517: Unspecified vulnerability (bsc#1104668)

CVE-2018-1656: Unspecified vulnerability (bsc#1104668)

CVE-2018-12539: Users other than the process owner might have been
able to use Java Attach API to connect to an IBM JVM on the same
machine and use Attach API operations, which includes the ability to
execute untrusted native code (bsc#1104668)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0705/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3732/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3736/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12539/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1517/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1656/"
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
    value:"https://www.suse.com/security/cve/CVE-2018-2964/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2973/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182839-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b60283f2"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-1987=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-1987=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-1987=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2018-1987=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-1987=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-1987=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-1987=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-1987=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0705");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"java-1_8_0-ibm-alsa-1.8.0_sr5.20-30.36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"java-1_8_0-ibm-plugin-1.8.0_sr5.20-30.36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-ibm-1.8.0_sr5.20-30.36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-ibm-devel-1.8.0_sr5.20-30.36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-ibm-alsa-1.8.0_sr5.20-30.36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-ibm-plugin-1.8.0_sr5.20-30.36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-ibm-1.8.0_sr5.20-30.36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-ibm-alsa-1.8.0_sr5.20-30.36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-ibm-plugin-1.8.0_sr5.20-30.36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-ibm-1.8.0_sr5.20-30.36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-ibm-devel-1.8.0_sr5.20-30.36.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_8_0-ibm");
}
