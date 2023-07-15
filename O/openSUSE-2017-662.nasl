#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-662.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100707);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-3509", "CVE-2017-3511", "CVE-2017-3512", "CVE-2017-3514", "CVE-2017-3526", "CVE-2017-3533", "CVE-2017-3539", "CVE-2017-3544");

  script_name(english:"openSUSE Security Update : java-1_8_0-openjdk (openSUSE-2017-662)");
  script_summary(english:"Check for the openSUSE-2017-662 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_8_0-openjdk fixes the following issues :

  - Upgrade to version jdk8u131 (icedtea 3.4.0) -
    bsc#1034849

  - Security fixes

  - S8163520, CVE-2017-3509: Reuse cache entries

  - S8163528, CVE-2017-3511: Better library loading

  - S8165626, CVE-2017-3512: Improved window framing

  - S8167110, CVE-2017-3514: Windows peering issue

  - S8168699: Validate special case invocations

  - S8169011, CVE-2017-3526: Resizing XML parse trees

  - S8170222, CVE-2017-3533: Better transfers of files

  - S8171121, CVE-2017-3539: Enhancing jar checking

  - S8171533, CVE-2017-3544: Better email transfer

  - S8172299: Improve class processing

  - New features

  - PR1969: Add AArch32 JIT port

  - PR3297: Allow Shenandoah to be used on AArch64

  - PR3340: jstack.stp should support AArch64

  - Import of OpenJDK 8 u131 build 11

  - S6474807: (smartcardio) CardTerminal.connect() throws
    CardException instead of CardNotPresentException

  - S6515172, PR3346: Runtime.availableProcessors() ignores
    Linux taskset command

  - S7155957:
    closed/java/awt/MenuBar/MenuBarStress1/MenuBarStress1.ja
    va hangs on win 64 bit with jdk8

  - S7167293: FtpURLConnection connection leak on
    FileNotFoundException

  - S8035568: [macosx] Cursor management unification

  - S8079595: Resizing dialog which is JWindow parent makes
    JVM crash

  - S8130769: The new menu can't be shown on the menubar
    after clicking the 'Add' button.

  - S8146602:
    jdk/test/sun/misc/URLClassPath/ClassnameCharTest.java
    test fails with NullPointerException

  - S8147842: IME Composition Window is displayed at
    incorrect location

  - S8147910, PR3346: Cache initial active_processor_count

  - S8150490: Update OS detection code to recognize Windows
    Server 2016

  - S8160951: [TEST_BUG]
    javax/xml/bind/marshal/8134111/UnmarshalTest.java should
    be added into :needs_jre group

  - S8160958: [TEST_BUG]
    java/net/SetFactoryPermission/SetFactoryPermission.java
    should be added into :needs_compact2 group

  - S8161147: jvm crashes when -XX:+UseCountedLoopSafepoints
    is enabled

  - S8161195: Regression:
    closed/javax/swing/text/FlowView/LayoutTest.java

  - S8161993, PR3346: G1 crashes if active_processor_count
    changes during startup

  - S8162876: [TEST_BUG]
    sun/net/www/protocol/http/HttpInputStream.java fails
    intermittently

  - S8162916: Test sun/security/krb5/auto/UnboundSSL.java
    fails

  - S8164533:
    sun/security/ssl/SSLSocketImpl/CloseSocket.java failed
    with 'Error while cleaning up threads after test'

  - S8167179: Make XSL generated namespace prefixes local to
    transformation process

  - S8168774: Polymorhic signature method check crashes
    javac

  - S8169465: Deadlock in com.sun.jndi.ldap.pool.Connections

  - S8169589: [macosx] Activating a JDialog puts to back
    another dialog

  - S8170307: Stack size option -Xss is ignored

  - S8170316: (tz) Support tzdata2016j

  - S8170814: Reuse cache entries (part II)

  - S8170888, PR3314, RH1284948: [linux] Experimental
    support for cgroup memory limits in container (ie
    Docker) environments

  - S8171388: Update JNDI Thread contexts

  - S8171949: [macosx] AWT_ZoomFrame Automated tests fail
    with error: The bitwise mask Frame.ICONIFIED is not
    setwhen the frame is in ICONIFIED state

  - S8171952: [macosx]
    AWT_Modality/Automated/ModalExclusion/NoExclusion/Modele
    ssDialog test fails as DummyButton on Dialog did not
    gain focus when &#9; clicked.

  - S8173030: Temporary backout fix #8035568 from 8u131-b03

  - S8173031: Temporary backout fix #8171952 from 8u131-b03

  - S8173783, PR3328: IllegalArgumentException:
    jdk.tls.namedGroups

  - S8173931: 8u131 L10n resource file update

  - S8174844: Incorrect GPL header causes RE script to miss
    swap to commercial header for licensee source bundle

  - S8174985: NTLM authentication doesn't work with IIS if
    NTLM cache is disabled

  - S8176044: (tz) Support tzdata2017a

  - Backports

  - S6457406, PR3335: javadoc doesn't handle <a
    href='http://...'> properly in producing index pages

  - S8030245, PR3335: Update langtools to use
    try-with-resources and multi-catch

  - S8030253, PR3335: Update langtools to use
    strings-in-switch

  - S8030262, PR3335: Update langtools to use foreach loops

  - S8031113, PR3337: TEST_BUG:
    java/nio/channels/AsynchronousChannelGroup/Basic.java
    fails intermittently

  - S8031625, PR3335: javadoc problems referencing inner
    class constructors

  - S8031649, PR3335: Clean up javadoc tests

  - S8031670, PR3335: Remove unneeded -source options in
    javadoc tests

  - S8032066, PR3335: Serialized form has broken links to
    non private inner classes of package private

  - S8034174, PR2290: Remove use of JVM_* functions from
    java.net code

  - S8034182, PR2290: Misc. warnings in java.net code

  - S8035876, PR2290: AIX build issues after '8034174:
    Remove use of JVM_* functions from java.net code'

  - S8038730, PR3335: Clean up the way JavadocTester is
    invoked, and checks for errors.

  - S8040903, PR3335: Clean up use of BUG_ID in javadoc
    tests

  - S8040904, PR3335: Ensure javadoc tests do not overwrite
    results within tests

  - S8040908, PR3335: javadoc test TestDocEncoding should
    use

    -notimestamp

  - S8041150, PR3335: Avoid silly use of static methods in
    JavadocTester

  - S8041253, PR3335: Avoid redundant synonyms of NO_TEST

  - S8043780, PR3368: Use open(O_CLOEXEC) instead of
    fcntl(FD_CLOEXEC)

  - S8061305, PR3335: Javadoc crashes when method name ends
    with 'Property'

  - S8072452, PR3337: Support DHE sizes up to 8192-bits and
    DSA sizes up to 3072-bits

  - S8075565, PR3337: Define @intermittent jtreg keyword and
    mark intermittently failing jdk tests

  - S8075670, PR3337: Remove intermittent keyword from some
    tests

  - S8078334, PR3337: Mark regression tests using randomness

  - S8078880, PR3337: Mark a few more intermittently
    failuring security-libs

  - S8133318, PR3337: Exclude intermittent failing PKCS11
    tests on Solaris SPARC 11.1 and earlier

  - S8144539, PR3337: Update PKCS11 tests to run with
    security manager

  - S8144566, PR3352: Custom HostnameVerifier disables SNI
    extension

  - S8153711, PR3313, RH1284948: [REDO] JDWP: Memory Leak:
    GlobalRefs never deleted when processing invokeMethod
    command

  - S8155049, PR3352: New tests from 8144566 fail with 'No
    expected Server Name Indication'

  - S8173941, PR3326: SA does not work if executable is DSO

  - S8174164, PR3334, RH1417266:
    SafePointNode::_replaced_nodes breaks with irreducible
    loops

  - S8174729, PR3336, RH1420518: Race Condition in
    java.lang.reflect.WeakCache

  - S8175097, PR3334, RH1417266: [TESTBUG] 8174164 fix
    missed the test

  - Bug fixes

  - PR3348: Architectures unsupported by SystemTap tapsets
    throw a parse error

  - PR3378: Perl should be mandatory

  - PR3389: javac.in and javah.in should use @PERL@ rather
    than a hardcoded path

  - AArch64 port

  - S8168699, PR3372: Validate special case invocations
    [AArch64 support]

  - S8170100, PR3372: AArch64: Crash in C1-compiled code
    accessing References

  - S8172881, PR3372: AArch64: assertion failure: the int
    pressure is incorrect

  - S8173472, PR3372: AArch64: C1 comparisons with null only
    use 32-bit instructions

  - S8177661, PR3372: Correct ad rule output register types
    from iRegX to iRegXNoSp

  - AArch32 port

  - PR3380: Zero should not be enabled by default on arm
    with the AArch32 HotSpot build

  - PR3384, S8139303, S8167584: Add support for AArch32
    architecture to configure and jdk makefiles

  - PR3385: aarch32 does not support -Xshare:dump

  - PR3386, S8164652: AArch32 jvm.cfg wrong for C1 build

  - PR3387: Installation fails on arm with AArch32 port as
    INSTALL_ARCH_DIR is arm, not aarch32

  - PR3388: Wrong path for jvm.cfg being used on arm with
    AArch32 build

  - Shenandoah

  - Fix Shenandoah argument checking on 32bit builds.

  - Import from Shenandoah tag
    aarch64-shenandoah-jdk8u101-b14-shenandoah-merge-2016-07
    -25

  - Import from Shenandoah tag
    aarch64-shenandoah-jdk8u121-b14-shenandoah-merge-2017-02
    -20

  - Import from Shenandoah tag
    aarch64-shenandoah-jdk8u121-b14-shenandoah-merge-2017-03
    -06

  - Import from Shenandoah tag
    aarch64-shenandoah-jdk8u121-b14-shenandoah-merge-2017-03
    -09

  - Import from Shenandoah tag
    aarch64-shenandoah-jdk8u121-b14-shenandoah-merge-2017-03
    -23

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://...'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034849"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_8_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-1.8.0.131-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-accessibility-1.8.0.131-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.131-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-debugsource-1.8.0.131-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-demo-1.8.0.131-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.131-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-devel-1.8.0.131-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.131-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-headless-1.8.0.131-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.131-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-javadoc-1.8.0.131-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-src-1.8.0.131-10.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_8_0-openjdk / java-1_8_0-openjdk-accessibility / etc");
}
