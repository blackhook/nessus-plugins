#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2143-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(139404);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2020-14556",
    "CVE-2020-14562",
    "CVE-2020-14573",
    "CVE-2020-14577",
    "CVE-2020-14581",
    "CVE-2020-14583",
    "CVE-2020-14593",
    "CVE-2020-14621"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : java-11-openjdk (SUSE-SU-2020:2143-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for java-11-openjdk fixes the following issues :

Update to upstream tag jdk-11.0.8+10 (July 2020 CPU, bsc#1174157)

  - Security fixes :

  + JDK-8230613: Better ASCII conversions

  + JDK-8231800: Better listing of arrays

  + JDK-8232014: Expand DTD support

  + JDK-8233234: Better Zip Naming

  + JDK-8233239, CVE-2020-14562: Enhance TIFF support

  + JDK-8233255: Better Swing Buttons

  + JDK-8234032: Improve basic calendar services

  + JDK-8234042: Better factory production of certificates

  + JDK-8234418: Better parsing with CertificateFactory

  + JDK-8234836: Improve serialization handling

  + JDK-8236191: Enhance OID processing

  + JDK-8236867, CVE-2020-14573: Enhance Graal interface
    handling

  + JDK-8237117, CVE-2020-14556: Better ForkJoinPool
    behavior

  + JDK-8237592, CVE-2020-14577: Enhance certificate
    verification

  + JDK-8238002, CVE-2020-14581: Better matrix operations

  + JDK-8238013: Enhance String writing

  + JDK-8238804: Enhance key handling process

  + JDK-8238842: AIOOBE in
    GIFImageReader.initializeStringTable

  + JDK-8238843: Enhanced font handing

  + JDK-8238920, CVE-2020-14583: Better Buffer support

  + JDK-8238925: Enhance WAV file playback

  + JDK-8240119, CVE-2020-14593: Less Affine Transformations

  + JDK-8240482: Improved WAV file playback

  + JDK-8241379: Update JCEKS support

  + JDK-8241522: Manifest improved jar headers redux

  + JDK-8242136, CVE-2020-14621: Better XML namespace
    handling

  - Other changes :

  + JDK-6933331: (d3d/ogl) java.lang.IllegalStateException:
    Buffers have not been created

  + JDK-7124307: JSpinner and changing value by mouse

  + JDK-8022574: remove HaltNode code after uncommon trap
    calls

  + JDK-8039082: [TEST_BUG] Test
    java/awt/dnd/BadSerializationTest/BadSerializationTest.j
    ava fails

  + JDK-8040630: Popup menus and tooltips flicker with
    previous popup contents when first shown

  + JDK-8044365: (dc) MulticastSendReceiveTests.java failing
    with ENOMEM when joining group (OS X 10.9)

  + JDK-8048215: [TESTBUG]
    java/lang/management/ManagementFactory/ThreadMXBeanProxy
    .java Expected non-null LockInfo

  + JDK-8051349: nsk/jvmti/scenarios/sampling/SP06/sp06t003
    fails in nightly

  + JDK-8080353: JShell: Better error message on attempting
    to add default method

  + JDK-8139876: Exclude hanging nsk/stress/stack from
    execution with deoptimization enabled

  + JDK-8146090: java/lang/ref/ReachabilityFenceTest.java
    fails with

    -XX:+DeoptimizeALot

  + JDK-8153430: jdk regression test MletParserLocaleTest,
    ParserInfiniteLoopTest reduce default timeout

  + JDK-8156207: Resource allocated BitMaps are often
    cleared unnecessarily

  + JDK-8159740: JShell: corralled declarations do not have
    correct source to wrapper mapping

  + JDK-8175984: ICC_Profile has un-needed, not-empty
    finalize method

  + JDK-8176359: Frame#setMaximizedbounds not working
    properly in multi screen environments

  + JDK-8183369: RFC unconformity of HttpURLConnection with
    proxy

  + JDK-8187078: -XX:+VerifyOops finds numerous problems
    when running JPRT

  + JDK-8189861: Refactor CacheFind

  + JDK-8191169: java/net/Authenticator/B4769350.java failed
    intermittently

  + JDK-8191930: [Graal] emits unparseable XML into compile
    log

  + JDK-8193879: Java debugger hangs on method invocation

  + JDK-8196019: java/awt/Window/Grab/GrabTest.java fails on
    Windows

  + JDK-8196181: sun/java2d/GdiRendering/InsetClipping.java
    fails

  + JDK-8198000:
    java/awt/List/EmptyListEventTest/EmptyListEventTest.java
    debug assert on Windows

  + JDK-8198001: java/awt/Menu/WrongParentAfterRemoveMenu/
    /WrongParentAfterRemoveMenu.java debug assert on Windows

  + JDK-8198339: Test javax/swing/border/Test6981576.java is
    unstable

  + JDK-8200701: jdk/jshell/ExceptionsTest.java fails on
    Windows, after JDK-8198801

  + JDK-8203264: JNI exception pending in
    PlainDatagramSocketImpl.c:740

  + JDK-8203672: JNI exception pending in PlainSocketImpl.c

  + JDK-8203673: JNI exception pending in
    DualStackPlainDatagramSocketImpl.c:398

  + JDK-8204834: Fix confusing 'allocate' naming in
    OopStorage

  + JDK-8205399: Set node color on pinned HashMap.TreeNode
    deletion

  + JDK-8205653:
    test/jdk/sun/management/jmxremote/bootstrap/
    /RmiRegistrySslTest.java and RmiSslBootstrapTest.sh fail
    with handshake_failure

  + JDK-8206179: com/sun/management/OperatingSystemMXBean/
    /GetCommittedVirtualMemorySize.java fails with Committed
    virtual memory size illegal value

  + JDK-8207334: VM times out in
    VM_HandshakeAllThreads::doit() with RunThese30M

  + JDK-8208277: Code cache heap (-XX:ReservedCodeCacheSize)
    doesn't work with 1GB LargePages

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174157");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14556/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14562/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14573/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14577/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14581/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14583/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14593/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14621/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202143-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?230bf65c");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-2143=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-2143=1

SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Packagehub-Subpackages-15-SP2-2020-2143=1

SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Packagehub-Subpackages-15-SP1-2020-2143=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2020-2143=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-2143=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-2143=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-2143=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14556");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14583");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-11-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-11-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-11-openjdk-headless");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-11-openjdk-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-11-openjdk-debuginfo-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-11-openjdk-debugsource-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-11-openjdk-demo-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-11-openjdk-devel-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-11-openjdk-headless-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-11-openjdk-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-11-openjdk-debuginfo-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-11-openjdk-debugsource-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-11-openjdk-demo-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-11-openjdk-devel-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-11-openjdk-headless-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"java-11-openjdk-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"java-11-openjdk-debuginfo-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"java-11-openjdk-debugsource-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"java-11-openjdk-demo-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"java-11-openjdk-devel-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"java-11-openjdk-headless-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"java-11-openjdk-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"java-11-openjdk-debuginfo-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"java-11-openjdk-debugsource-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"java-11-openjdk-demo-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"java-11-openjdk-devel-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"java-11-openjdk-headless-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"java-11-openjdk-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"java-11-openjdk-debuginfo-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"java-11-openjdk-debugsource-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"java-11-openjdk-demo-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"java-11-openjdk-devel-11.0.8.0-3.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"java-11-openjdk-headless-11.0.8.0-3.45.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-11-openjdk");
}
