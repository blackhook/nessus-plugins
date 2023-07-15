#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2175-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102541);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10078", "CVE-2017-10081", "CVE-2017-10086", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10105", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10111", "CVE-2017-10114", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10118", "CVE-2017-10125", "CVE-2017-10135", "CVE-2017-10176", "CVE-2017-10193", "CVE-2017-10198", "CVE-2017-10243");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : java-1_8_0-openjdk (SUSE-SU-2017:2175-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This java-1_8_0-openjdk update to version jdk8u141 (icedtea 3.5.0)
fixes the following issues: Security issues fixed :

  - CVE-2017-10053: Improved image post-processing steps
    (bsc#1049305)

  - CVE-2017-10067: Additional jar validation steps
    (bsc#1049306)

  - CVE-2017-10074: Image conversion improvements
    (bsc#1049307)

  - CVE-2017-10078: Better script accessibility for
    JavaScript (bsc#1049308)

  - CVE-2017-10081: Right parenthesis issue (bsc#1049309)

  - CVE-2017-10086: Unspecified vulnerability in
    subcomponent JavaFX (bsc#1049310)

  - CVE-2017-10087: Better Thread Pool execution
    (bsc#1049311)

  - CVE-2017-10089: Service Registration Lifecycle
    (bsc#1049312)

  - CVE-2017-10090: Better handling of channel groups
    (bsc#1049313)

  - CVE-2017-10096: Transform Transformer Exceptions
    (bsc#1049314)

  - CVE-2017-10101: Better reading of text catalogs
    (bsc#1049315)

  - CVE-2017-10102: Improved garbage collection
    (bsc#1049316)

  - CVE-2017-10105: Unspecified vulnerability in
    subcomponent deployment (bsc#1049317)

  - CVE-2017-10107: Less Active Activations (bsc#1049318)

  - CVE-2017-10108: Better naming attribution (bsc#1049319)

  - CVE-2017-10109: Better sourcing of code (bsc#1049320)

  - CVE-2017-10110: Better image fetching (bsc#1049321)

  - CVE-2017-10111: Rearrange MethodHandle arrangements
    (bsc#1049322)

  - CVE-2017-10114: Unspecified vulnerability in
    subcomponent JavaFX (bsc#1049323)

  - CVE-2017-10115: Higher quality DSA operations
    (bsc#1049324)

  - CVE-2017-10116: Proper directory lookup processing
    (bsc#1049325)

  - CVE-2017-10118: Higher quality ECDSA operations
    (bsc#1049326)

  - CVE-2017-10125: Unspecified vulnerability in
    subcomponent deployment (bsc#1049327)

  - CVE-2017-10135: Better handling of PKCS8 material
    (bsc#1049328)

  - CVE-2017-10176: Additional elliptic curve support
    (bsc#1049329)

  - CVE-2017-10193: Improve algorithm constraints
    implementation (bsc#1049330)

  - CVE-2017-10198: Clear certificate chain connections
    (bsc#1049331)

  - CVE-2017-10243: Unspecified vulnerability in
    subcomponent JAX-WS (bsc#1049332) Bug fixes :

  - Check registry registration location

  - Improved certificate processing

  - JMX diagnostic improvements

  - Update to libpng 1.6.28

  - Import of OpenJDK 8 u141 build 15 (bsc#1049302) New
    features :

  - Support using RSAandMGF1 with the SHA hash algorithms in
    the PKCS11 provider

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049329"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10053/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10067/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10074/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10078/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10081/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10086/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10087/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10089/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10090/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10096/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10101/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10102/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10105/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10107/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10108/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10109/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10110/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10111/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10114/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10115/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10116/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10118/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10125/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10135/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10176/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10193/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10198/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10243/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172175-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1410fd1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 6:zypper in -t patch
SUSE-OpenStack-Cloud-6-2017-1337=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2017-1337=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1337=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2017-1337=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1337=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-1337=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-1337=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1337=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/17");
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
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-debugsource-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-demo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-devel-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-headless-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-debugsource-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-demo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-devel-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-headless-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-debugsource-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-demo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-devel-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-headless-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-debugsource-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-debugsource-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-1.8.0.144-27.5.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.144-27.5.3")) flag++;


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
