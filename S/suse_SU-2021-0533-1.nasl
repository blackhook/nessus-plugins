#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0533-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(146653);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-14803");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"SUSE SLES12 Security Update : java-1_8_0-openjdk (SUSE-SU-2021:0533-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for java-1_8_0-openjdk fixes the following issues :

Update to version jdk8u282 (icedtea 3.18.0)

  - January 2021 CPU (bsc#1181239)

  - Security fixes

  + JDK-8247619: Improve Direct Buffering of Characters
    (CVE-2020-14803)

  - Import of OpenJDK 8 u282 build 01

  + JDK-6962725: Regtest javax/swing/JFileChooser/6738668/
    /bug6738668.java fails under Linux

  + JDK-8025936: Windows .pdb and .map files does not have
    proper dependencies setup

  + JDK-8030350: Enable additional compiler warnings for GCC

  + JDK-8031423: Test java/awt/dnd/DisposeFrameOnDragCrash/
    /DisposeFrameOnDragTest.java fails by Timeout on Windows

  + JDK-8036122: Fix warning 'format not a string literal'

  + JDK-8051853: new
    URI('x/').resolve('..').getSchemeSpecificPart() returns
    null!

  + JDK-8132664:
    closed/javax/swing/DataTransfer/DefaultNoDrop/
    /DefaultNoDrop.java locks on Windows

  + JDK-8134632: Mark javax/sound/midi/Devices/
    /InitializationHang.java as headful

  + JDK-8148854: Class names 'SomeClass' and 'LSomeClass;'
    treated by JVM as an equivalent

  + JDK-8148916: Mark bug6400879.java as intermittently
    failing

  + JDK-8148983: Fix extra comma in changes for JDK-8148916

  + JDK-8160438:
    javax/swing/plaf/nimbus/8057791/bug8057791.java fails

  + JDK-8165808: Add release barriers when allocating
    objects with concurrent collection

  + JDK-8185003: JMX: Add a version of
    ThreadMXBean.dumpAllThreads with a maxDepth argument

  + JDK-8202076: test/jdk/java/io/File/WinSpecialFiles.java
    on windows with VS2017

  + JDK-8207766: [testbug] Adapt tests for Aix.

  + JDK-8212070: Introduce diagnostic flag to abort VM on
    failed JIT compilation

  + JDK-8213448: [TESTBUG] enhance jfr/jvm/TestDumpOnCrash

  + JDK-8215727: Restore JFR thread sampler loop to old /
    previous behavior

  + JDK-8220657: JFR.dump does not work when filename is set

  + JDK-8221342: [TESTBUG] Generate Dockerfile for docker
    testing

  + JDK-8224502: [TESTBUG] JDK docker test
    TestSystemMetrics.java fails with access issues and OOM

  + JDK-8231209: [REDO]
    ThreadMXBean::getThreadAllocatedBytes() can be quicker
    for self thread

  + JDK-8231968: getCurrentThreadAllocatedBytes default
    implementation s/b getThreadAllocatedBytes

  + JDK-8232114: JVM crashed at imjpapi.dll in native code

  + JDK-8234270: [REDO] JDK-8204128 NMT might report
    incorrect numbers for Compiler area

  + JDK-8234339: replace JLI_StrTok in java_md_solinux.c

  + JDK-8238448: RSASSA-PSS signature verification fail when
    using certain odd key sizes

  + JDK-8242335: Additional Tests for RSASSA-PSS

  + JDK-8244225: stringop-overflow warning on strncpy call
    from compile_the_world_in

  + JDK-8245400: Upgrade to LittleCMS 2.11

  + JDK-8248214: Add paddings for TaskQueueSuper to reduce
    false-sharing cache contention

  + JDK-8249176: Update GlobalSignR6CA test certificates

  + JDK-8250665: Wrong translation for the month name of May
    in ar_JO,LB,SY

  + JDK-8250928: JFR: Improve hash algorithm for stack
    traces

  + JDK-8251469: Better cleanup for
    test/jdk/javax/imageio/SetOutput.java

  + JDK-8251840:
    Java_sun_awt_X11_XToolkit_getDefaultScreenData should
    not be in make/mapfiles/libawt_xawt/mapfile-vers

  + JDK-8252384: [TESTBUG] Some tests refer to COMPAT
    provider rather than JRE

  + JDK-8252395: [8u] --with-native-debug-symbols=external
    doesn't include debuginfo files for binaries

  + JDK-8252497: Incorrect numeric currency code for ROL

  + JDK-8252754: Hash code calculation of JfrStackTrace is
    inconsistent

  + JDK-8252904: VM crashes when JFR is used and JFR event
    class is transformed

  + JDK-8252975: [8u] JDK-8252395 breaks the build for

    --with-native-debug-symbols=internal

  + JDK-8253284: Zero OrderAccess barrier mappings are
    incorrect

  + JDK-8253550: [8u] JDK-8252395 breaks the build for make
    STRIP_POLICY=no_strip

  + JDK-8253752: test/sun/management/jmxremote/bootstrap/
    /RmiBootstrapTest.java fails randomly

  + JDK-8254081: java/security/cert/PolicyNode/
    /GetPolicyQualifiers.java fails due to an expired
    certificate

  + JDK-8254144: Non-x86 Zero builds fail with return-type
    warning in os_linux_zero.cpp

  + JDK-8254166: Zero: return-type warning in
    zeroInterpreter_zero.cpp

  + JDK-8254683: [TEST_BUG] jdk/test/sun/tools/jconsole/
    /WorkerDeadlockTest.java fails

  + JDK-8255003: Build failures on Solaris

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181239");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14803/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210533-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac2b5ffa");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 9 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-9-2021-533=1

SUSE OpenStack Cloud Crowbar 8 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-8-2021-533=1

SUSE OpenStack Cloud 9 :

zypper in -t patch SUSE-OpenStack-Cloud-9-2021-533=1

SUSE OpenStack Cloud 8 :

zypper in -t patch SUSE-OpenStack-Cloud-8-2021-533=1

SUSE OpenStack Cloud 7 :

zypper in -t patch SUSE-OpenStack-Cloud-7-2021-533=1

SUSE Linux Enterprise Server for SAP 12-SP4 :

zypper in -t patch SUSE-SLE-SAP-12-SP4-2021-533=1

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2021-533=1

SUSE Linux Enterprise Server for SAP 12-SP2 :

zypper in -t patch SUSE-SLE-SAP-12-SP2-2021-533=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2021-533=1

SUSE Linux Enterprise Server 12-SP4-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-LTSS-2021-533=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2021-533=1

SUSE Linux Enterprise Server 12-SP3-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-BCL-2021-533=1

SUSE Linux Enterprise Server 12-SP2-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-2021-533=1

SUSE Linux Enterprise Server 12-SP2-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-BCL-2021-533=1

HPE Helion Openstack 8 :

zypper in -t patch HPE-Helion-OpenStack-8-2021-533=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/22");

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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_8_0-openjdk-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_8_0-openjdk-debugsource-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_8_0-openjdk-demo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_8_0-openjdk-devel-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_8_0-openjdk-headless-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-debugsource-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-demo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-devel-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-headless-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-debugsource-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-demo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-devel-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-headless-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_8_0-openjdk-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_8_0-openjdk-debugsource-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_8_0-openjdk-demo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_8_0-openjdk-devel-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_8_0-openjdk-headless-1.8.0.282-27.56.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.282-27.56.2")) flag++;


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
