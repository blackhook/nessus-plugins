#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-818.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123345);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-3136", "CVE-2018-3139", "CVE-2018-3149", "CVE-2018-3150", "CVE-2018-3157", "CVE-2018-3169", "CVE-2018-3180", "CVE-2018-3183");

  script_name(english:"openSUSE Security Update : java-11-openjdk (openSUSE-2019-818)");
  script_summary(english:"Check for the openSUSE-2019-818 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-11-openjdk fixes the following issues :

Update to upstream tag jdk-11.0.1+13 (Oracle October 2018 CPU)

Security fixes :

  - S8202936, CVE-2018-3183, bsc#1112148: Improve script
    engine support

  - S8199226, CVE-2018-3169, bsc#1112146: Improve field
    accesses

  - S8199177, CVE-2018-3149, bsc#1112144: Enhance JNDI
    lookups

  - S8202613, CVE-2018-3180, bsc#1112147: Improve TLS
    connections stability

  - S8208209, CVE-2018-3180, bsc#1112147: Improve TLS
    connection stability again

  - S8199172, CVE-2018-3150, bsc#1112145: Improve jar
    attribute checks

  - S8200648, CVE-2018-3157, bsc#1112149: Make midi code
    more sound

  - S8194534, CVE-2018-3136, bsc#1112142: Manifest better
    support

  - S8208754, CVE-2018-3136, bsc#1112142: The fix for
    JDK-8194534 needs updates

  - S8196902, CVE-2018-3139, bsc#1112143: Better HTTP
    Redirection

Security-In-Depth fixes :

  - S8194546: Choosier FileManagers

  - S8195874: Improve jar specification adherence

  - S8196897: Improve PRNG support

  - S8197881: Better StringBuilder support

  - S8201756: Improve cipher inputs

  - S8203654: Improve cypher state updates

  - S8204497: Better formatting of decimals

  - S8200666: Improve LDAP support

  - S8199110: Address Internet Addresses

Update to upstream tag jdk-11+28 (OpenJDK 11 rc1)

  - S8207317: SSLEngine negotiation fail exception behavior
    changed from fail-fast to fail-lazy

  - S8207838: AArch64: Float registers incorrectly restored
    in JNI call

  - S8209637: [s390x] Interpreter doesn't call result
    handler after native calls

  - S8209670: CompilerThread releasing code buffer in
    destructor is unsafe

  - S8209735: Disable avx512 by default

  - S8209806: API docs should be updated to refer to
    javase11

  - Report version without the '-internal' postfix

  - Don't build against gdk making the accessibility depend
    on a particular version of gtk.

Update to upstream tag jdk-11+27

  - S8031761: [TESTBUG] Add a regression test for
    JDK-8026328

  - S8151259: [TESTBUG]
    nsk/jvmti/RedefineClasses/redefclass030 fails with
    'unexpected values of outer fields of the class' when
    running with -Xcomp

  - S8164639: Configure PKCS11 tests to use user-supplied
    NSS libraries

  - S8189667: Desktop#moveToTrash expects incorrect '<<ALL
    FILES>>' FilePermission

  - S8194949: [Graal] gc/TestNUMAPageSize.java fail with OOM
    in

    -Xcomp

  - S8195156: [Graal] serviceability/jvmti/GetModulesInfo/
    /JvmtiGetAllModulesTest.java fails with Graal in Xcomp
    mode

  - S8199081: [Testbug] compiler/linkage/LinkageErrors.java
    fails if run twice

  - S8201394: Update java.se module summary to reflect
    removal of java.se.ee module

  - S8204931: Colors with alpha are painted incorrectly on
    Linux

  - S8204966: [TESTBUG] hotspot/test/compiler/whitebox/
    /IsMethodCompilableTest.java test fails with

    -XX:CompileThreshold=1

  - S8205608: Fix 'frames()' in ThreadReferenceImpl.c to
    prevent quadratic runtime behavior

  - S8205687: TimeoutHandler generates huge core files

  - S8206176: Remove the temporary tls13VN field

  - S8206258: [Test Error] sun/security/pkcs11 tests fail if
    NSS libs not found

  - S8206965: java/util/TimeZone/Bug8149452.java failed on
    de_DE and ja_JP locale.

  - S8207009: TLS 1.3 half-close and synchronization issues

  - S8207046: arm32 vm crash: C1 arm32 platform functions
    parameters type mismatch

  - S8207139: NMT is not enabled on Windows 2016/10

  - S8207237: SSLSocket#setEnabledCipherSuites is accepting
    empty string

  - S8207355: C1 compilation hangs in
    ComputeLinearScanOrder::compute_dominator

  - S8207746: C2: Lucene crashes on AVX512 instruction

  - S8207765: HeapMonitorTest.java intermittent failure

  - S8207944: java.lang.ClassFormatError: Extra bytes at the
    end of class file test' possibly violation of JVMS 4.7.1

  - S8207948: JDK 11 L10n resource file update msg drop 10

  - S8207966: HttpClient response without content-length
    does not return body

  - S8208125: Cannot input text into JOptionPane Text Input
    Dialog

  - S8208164: (str) improve specification of String::lines

  - S8208166: Still unable to use custom SSLEngine with
    default TrustManagerFactory after JDK-8207029

  - S8208189: ProblemList
    compiler/graalunit/JttThreadsTest.java

  - S8208205: ProblemList tests that fail due to 'Error
    attaching to process: Can't create thread_db agent!'

  - S8208226: ProblemList
    com/sun/jdi/BasicJDWPConnectionTest.java

  - S8208251: serviceability/jvmti/HeapMonitor/MyPackage/
    /HeapMonitorGCCMSTest.java fails intermittently on
    Linux-X64

  - S8208305: ProblemList
    compiler/jvmci/compilerToVM/GetFlagValueTest.java

  - S8208347: ProblemList
    compiler/cpuflags/TestAESIntrinsicsOnSupportedConfig.jav
    a

  - S8208353: Upgrade JDK 11 to libpng 1.6.35

  - S8208358: update bug ids mentioned in tests

  - S8208370: fix typo in ReservedStack tests' @requires

  - S8208391: Differentiate response and connect timeouts in
    HTTP Client API

  - S8208466: Fix potential memory leak in harfbuzz shaping.

  - S8208496: New Test to verify concurrent behavior of TLS.

  - S8208521: ProblemList more tests that fail due to 'Error
    attaching to process: Can't create thread_db agent!'

  - S8208640: [a11y] [macos] Unable to navigate between
    Radiobuttons in Radio group using keyboard.

  - S8208663: JDK 11 L10n resource file update msg drop 20

  - S8208676: Missing NULL check and resource leak in
    NetworkPerformanceInterface::NetworkPerformance::network
    _utilization

  - S8208691: Tighten up jdk.includeInExceptions security
    property

  - S8209011: [TESTBUG] AArch64: sun/security/pkcs11/Secmod/
    /TestNssDbSqlite.java fails in aarch64 platforms

  - S8209029: ProblemList tests that fail due to 'Error
    attaching to process: Can't create thread_db agent!' in
    jdk-11+25 testing

  - S8209149: [TESTBUG] runtime/RedefineTests/
    /RedefineRunningMethods.java needs a longer timeout

  - S8209451: Please change jdk 11 milestone to FCS

  - S8209452: VerifyCACerts.java failed with 'At least one
    cacert test failed'

  - S8209506: Add Google Trust Services GlobalSign root
    certificates

  - S8209537: Two security tests failed after JDK-8164639
    due to dependency was missed

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112149"
  );
  # https://features.opensuse.org/323970
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/"
  );
  # https://features.opensuse.org/324453
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-11-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-accessibility-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-11.0.1.0-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-accessibility-11.0.1.0-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-accessibility-debuginfo-11.0.1.0-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-debuginfo-11.0.1.0-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-debugsource-11.0.1.0-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-demo-11.0.1.0-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-devel-11.0.1.0-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-headless-11.0.1.0-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-javadoc-11.0.1.0-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-jmods-11.0.1.0-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-11-openjdk-src-11.0.1.0-lp150.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-11-openjdk / java-11-openjdk-accessibility / etc");
}
