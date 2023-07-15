#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3359-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(143712);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-14779",
    "CVE-2020-14781",
    "CVE-2020-14782",
    "CVE-2020-14792",
    "CVE-2020-14796",
    "CVE-2020-14797",
    "CVE-2020-14798",
    "CVE-2020-14803"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : java-11-openjdk (SUSE-SU-2020:3359-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for java-11-openjdk fixes the following issues :

Update to upstream tag jdk-11.0.9-11 (October 2020 CPU, bsc#1177943)

  - New features

  + JDK-8250784: Shenandoah: A Low-Pause-Time Garbage
    Collector

  - Security fixes

  + JDK-8233624: Enhance JNI linkage

  + JDK-8236196: Improve string pooling

  + JDK-8236862, CVE-2020-14779: Enhance support of Proxy
    class

  + JDK-8237990, CVE-2020-14781: Enhanced LDAP contexts

  + JDK-8237995, CVE-2020-14782: Enhance certificate
    processing

  + JDK-8240124: Better VM Interning

  + JDK-8241114, CVE-2020-14792: Better range handling

  + JDK-8242680, CVE-2020-14796: Improved URI Support

  + JDK-8242685, CVE-2020-14797: Better Path Validation

  + JDK-8242695, CVE-2020-14798: Enhanced buffer support

  + JDK-8243302: Advanced class supports

  + JDK-8244136, CVE-2020-14803: Improved Buffer supports

  + JDK-8244479: Further constrain certificates

  + JDK-8244955: Additional Fix for JDK-8240124

  + JDK-8245407: Enhance zoning of times

  + JDK-8245412: Better class definitions

  + JDK-8245417: Improve certificate chain handling

  + JDK-8248574: Improve jpeg processing

  + JDK-8249927: Specify limits of
    jdk.serialProxyInterfaceLimit

  + JDK-8253019: Enhanced JPEG decoding

  - Other changes

  + JDK-6532025: GIF reader throws misleading exception with
    truncated images

  + JDK-6949753: [TEST BUG]: java/awt/print/PageFormat/
    /PDialogTest.java needs update by removing an infinite
    loop

  + JDK-8022535: [TEST BUG] javax/swing/text/html/parser/
    /Test8017492.java fails

  + JDK-8062947: Fix exception message to correctly
    represent LDAP connection failure

  + JDK-8067354: com/sun/jdi/GetLocalVariables4Test.sh
    failed

  + JDK-8134599: TEST_BUG:
    java/rmi/transport/closeServerSocket/
    /CloseServerSocket.java fails intermittently with
    Address already in use

  + JDK-8151678: com/sun/jndi/ldap/LdapTimeoutTest.java
    failed due to timeout on DeadServerNoTimeoutTest is
    incorrect

  + JDK-8160768: Add capability to custom resolve
    host/domain names within the default JNDI LDAP provider

  + JDK-8172404: Tools should warn if weak algorithms are
    used before restricting them

  + JDK-8193367: Annotated type variable bounds crash javac

  + JDK-8202117:
    com/sun/jndi/ldap/RemoveNamingListenerTest.java fails
    intermittently: Connection reset

  + JDK-8203026: java.rmi.NoSuchObjectException: no such
    object in table

  + JDK-8203281: [Windows] JComboBox change in ui when
    editor.setBorder() is called

  + JDK-8203382: Rename
    SystemDictionary::initialize_wk_klass to
    resolve_wk_klass

  + JDK-8203393: com/sun/jdi/JdbMethodExitTest.sh and
    JdbExprTest.sh fail due to timeout

  + JDK-8203928: [Test] Convert non-JDB scaffolding
    serviceability shell script tests to java

  + JDK-8204963: javax.swing.border.TitledBorder has a
    memory leak

  + JDK-8204994: SA might fail to attach to process with
    'Windbg Error: WaitForEvent failed'

  + JDK-8205534: Remove SymbolTable dependency from
    serviceability agent

  + JDK-8206309: Tier1 SA tests fail

  + JDK-8208281: java/nio/channels/
    /AsynchronousSocketChannel/Basic.java timed out

  + JDK-8209109: [TEST] rewrite com/sun/jdi shell tests to
    java version

  - step1

  + JDK-8209332: [TEST]
    test/jdk/com/sun/jdi/CatchPatternTest.sh is incorrect

  + JDK-8209342: Problemlist SA tests on Solaris due to
    Error attaching to process: Can't create thread_db
    agent!

  + JDK-8209343: Test
    javax/swing/border/TestTitledBorderLeak.java should be
    marked as headful

  + JDK-8209517: com/sun/jdi/BreakpointWithFullGC.java fails
    with timeout

  + JDK-8209604: [TEST] rewrite com/sun/jdi shell tests to
    java version

  - step2

  + JDK-8209605: com/sun/jdi/BreakpointWithFullGC.java fails
    with ZGC

  + JDK-8209608: Problem list
    com/sun/jdi/BreakpointWithFullGC.java

  + JDK-8210131:
    vmTestbase/nsk/jvmti/scenarios/allocation/AP10/
    /ap10t001/TestDescription.java failed with ObjectFree:
    GetCurrentThreadCpuTimerInfo returned unexpected error
    code

  + JDK-8210243: [TEST] rewrite com/sun/jdi shell tests to
    java version

  - step3

  + JDK-8210527: JShell: NullPointerException in
    jdk.jshell.Eval.translateExceptionStack

  + JDK-8210560: [TEST] convert com/sun/jdi
    redefineClass-related tests

  + JDK-8210725: com/sun/jdi/RedefineClearBreakpoint.java
    fails with waitForPrompt timed out after 60 seconds

  + JDK-8210748: [TESTBUG] lib.jdb.Jdb.waitForPrompt()
    should clarify which output is the pending reply after a
    timeout

  + JDK-8210760: [TEST] rewrite com/sun/jdi shell tests to
    java version

  - step4

  + JDK-8210977:
    jdk/jfr/event/oldobject/TestThreadLocalLeak.java fails
    to find ThreadLocalObject

  + JDK-8211292: [TEST] convert
    com/sun/jdi/DeferredStepTest.sh test

  + JDK-8211694: JShell: Redeclared variable should be reset

  + JDK-8212200: assert when shared java.lang.Object is
    redefined by JVMTI agent

  + JDK-8212629: [TEST] wrong breakpoint in
    test/jdk/com/sun/jdi/DeferredStepTest

  + JDK-8212665: com/sun/jdi/DeferredStepTest.java: jj1
    (line 57)

  - unexpected. lastLine=52, minLine=52, maxLine=55

  + JDK-8212807: tools/jar/multiRelease/Basic.java times out

  + JDK-8213182: Minimal VM build failure after JDK-8212200
    (assert when shared java.lang.Object is redefined by
    JVMTI agent)

  + JDK-8213214: Set -Djava.io.tmpdir= when running tests

  + JDK-8213275: ReplaceCriticalClasses.java fails with
    jdk.internal.vm.PostVMInitHook not found

  + JDK-8213574: Deadlock in string table expansion when
    dumping lots of CDS classes

  + JDK-8213703: LambdaConversionException: Invalid receiver
    type not a subtype of implementation type interface

  + JDK-8214074: Ghash optimization using AVX instructions

  + JDK-8214491: Upgrade to JLine 3.9.0

  + JDK-8214797: TestJmapCoreMetaspace.java timed out

  + JDK-8215243: JShell tests failing intermitently with
    'Problem cleaning up the following threads:'

  + JDK-8215244: jdk/jshell/ToolBasicTest.java
    testHistoryReference failed

  + JDK-8215354: x86_32 build failures after JDK-8214074
    (Ghash optimization using AVX instructions)

  + JDK-8215438: jshell tool: Ctrl-D causes EOF

  + JDK-8216021: RunTest.gmk might set concurrency level to
    1 on Windows

  + JDK-8216974: HttpConnection not returned to the pool
    after 204 response

  + JDK-8218948: SimpleDateFormat :: format - Zone Names are
    not reflected correctly during run time

  + JDK-8219712: code_size2 (defined in
    stub_routines_x86.hpp) is too small on new Skylake CPUs

  + JDK-8220150: macos10.14 Mojave returns anti-aliased
    glyphs instead of aliased B&W glyphs

  + JDK-8221658: aarch64: add necessary predicate for ubfx
    patterns

  + JDK-8221759: Crash when completing 'java.io.File.path'

  + JDK-8221918: runtime/SharedArchiveFile/serviceability/
    /ReplaceCriticalClasses.java fails: Shared archive not
    found

  + JDK-8222074: Enhance auto vectorization for x86

  + JDK-8222079: Don't use memset to initialize fields
    decode_env constructor in disassembler.cpp

  + JDK-8222769: [TESTBUG] TestJFRNetworkEvents should not
    rely on hostname command

  + JDK-8223688: JShell: crash on the instantiation of raw
    anonymous class

  + JDK-8223777: In posix_spawn mode, failing to exec()
    jspawnhelper does not result in an error

  + JDK-8223940: Private key not supported by chosen
    signature algorithm

  + JDK-8224184: jshell got IOException at exiting with AIX

  + JDK-8224234: compiler/codegen/TestCharVect2.java fails
    in test_mulc

  + JDK-8225037: java.net.JarURLConnection::getJarEntry()
    throws NullPointerException

  + JDK-8225625: AES Electronic Codebook (ECB) encryption
    and decryption optimization using AVX512 + VAES
    instructions

  + JDK-8226536: Catch OOM from deopt that fails
    rematerializing objects

  + JDK-8226575: OperatingSystemMXBean should be made
    container aware

  + JDK-8226697: Several tests which need the @key headful
    keyword are missing it.

  + JDK-8226809: Circular reference in printed stack trace
    is not correctly indented & ambiguous

  + JDK-8227059: sun/security/tools/keytool/
    /DefaultSignatureAlgorithm.java timed out

  + JDK-8227269: Slow class loading when running with JDWP

  + JDK-8227595:
    keytool/fakegen/DefaultSignatureAlgorithm.java fails due
    to 'exitValue = 6'

  + JDK-8228448: Jconsole can't connect to itself

  + JDK-8228967: Trust/Key store and SSL context utilities
    for tests

  + JDK-8229378: jdwp library loader in linker_md.c quietly
    truncates on buffer overflow

  + JDK-8229815: Upgrade Jline to 3.12.1

  + JDK-8230000: some httpclients testng tests run zero test

  + JDK-8230002: javax/xml/jaxp/unittest/transform/
    /SecureProcessingTest.java runs zero test

  + JDK-8230010: Remove jdk8037819/BasicTest1.java

  + JDK-8230094: CCE in createXMLEventWriter(Result) over an
    arbitrary XMLStreamWriter

  + JDK-8230402: Allocation of compile task fails with
    assert: 'Leaking compilation tasks?'

  + JDK-8230767: FlightRecorderListener returns null
    recording

  + JDK-8230870: (zipfs) Add a ZIP FS test that is similar
    to test/jdk/java/util/zip/EntryCount64k.java

  + JDK-8231209: [REDO]
    ThreadMXBean::getThreadAllocatedBytes() can be quicker
    for self thread

  + JDK-8231586: enlarge encoding space for OopMapValue
    offsets

  + JDK-8231953: Wrong assumption in assertion in
    oop::register_oop

  + JDK-8231968: getCurrentThreadAllocatedBytes default
    implementation s/b getThreadAllocatedBytes

  + JDK-8232083: Minimal VM is broken after JDK-8231586

  + JDK-8232161: Align some one-way conversion in MS950
    charset with Windows

  + JDK-8232855: jshell missing word in /help help

  + JDK-8233027: OopMapSet::all_do does oms.next() twice
    during iteration

  + JDK-8233228: Disable weak named curves by default in
    TLS, CertPath, and Signed JAR

  + JDK-8233386: Initialize NULL fields for unused
    decorations

  + JDK-8233452: java.math.BigDecimal.sqrt() with
    RoundingMode.FLOOR results in incorrect result

  + JDK-8233686: XML transformer uses excessive amount of
    memory

  + JDK-8233741: AES Countermode (AES-CTR) optimization
    using AVX512 + VAES instructions

  + JDK-8233829: javac cannot find non-ASCII module name
    under non-UTF8 environment

  + JDK-8233958: Memory retention due to HttpsURLConnection
    finalizer that serves no purpose

  + JDK-8234011: (zipfs) Memory leak in
    ZipFileSystem.releaseDeflater()

  + JDK-8234058: runtime/CompressedOops/
    /CompressedClassPointers.java fails with 'Narrow klass
    base: 0x0000000000000000' missing from stdout/stderr

  + JDK-8234149: Several regression tests do not dispose
    Frame at end

  + JDK-8234347: 'Turkey' meta time zone does not generate
    composed localized names

  + JDK-8234385: [TESTBUG] java/awt/EventQueue/6980209/
    /bug6980209.java fails in linux nightly

  + JDK-8234535: Cross compilation fails due to missing
    CFLAGS for the BUILD_CC

  + JDK-8234541: C1 emits an empty message when it inlines
    successfully

  + JDK-8234687: change javap reporting on unknown
    attributes

  + JDK-8236464: SO_LINGER option is ignored by SSLSocket in
    JDK 11

  + JDK-8236548: Localized time zone name inconsistency
    between English and other locales

  + JDK-8236617: jtreg test containers/docker/
    /TestMemoryAwareness.java fails after 8226575

  + JDK-8237182: Update copyright header for shenandoah and
    epsilon files

  + JDK-8237888: security/infra/java/security/cert/
    /CertPathValidator/certification/LuxTrustCA.java fails
    when checking validity interval

  + JDK-8237977: Further update
    javax/net/ssl/compatibility/Compatibility.java

  + JDK-8238270: java.net HTTP/2 client does not decrease
    stream count when receives 204 response

  + JDK-8238284: [macos] Zero VM build fails due to an
    obvious typo

  + JDK-8238380: java.base/unix/native/libjava/childproc.c
    'multiple definition' link errors with GCC10

  + JDK-8238386: (sctp)
    jdk.sctp/unix/native/libsctp/SctpNet.c 'multiple
    definition' link errors with GCC10

  + JDK-8238388: libj2gss/NativeFunc.o 'multiple definition'
    link errors with GCC10

  + JDK-8238448: RSASSA-PSS signature verification fail when
    using certain odd key sizes

  + JDK-8238710: LingeredApp doesn't log stdout/stderr if
    exits with non-zero code

  + JDK-8239083: C1 assert(known_holder == NULL ||
    (known_holder->is_instance_klass() &&
    (!known_holder->is_interface() ||

((ciInstanceKlass*)known_holder)->has_nonstatic_concrete_methods())),
'shou ld be non-static concrete method');

  + JDK-8239385: KerberosTicket client name refers wrongly
    to sAMAccountName in AD

  + JDK-8240169: javadoc fails to link to non-modular api
    docs

  + JDK-8240295: hs_err elapsed time in seconds is not
    accurate enough

  + JDK-8240360: NativeLibraryEvent has wrong library name
    on Linux

  + JDK-8240676: Meet not symmetric failure when running
    lucene on jdk8

  + JDK-8241007: Shenandoah: remove
    ShenandoahCriticalControlThreadPriority support

  + JDK-8241065: Shenandoah: remove leftover code after
    JDK-8231086

  + JDK-8241086: Test runtime/NMT/HugeArenaTracking.java is
    failing on 32bit Windows

  + JDK-8241130:
    com.sun.jndi.ldap.EventSupport.removeDeadNotifier:
    java.lang.NullPointerException

  + JDK-8241138: http.nonProxyHosts=* causes
    StringIndexOutOfBoundsException in DefaultProxySelector

  + JDK-8241319: WB_GetCodeBlob doesn't have ResourceMark

  + JDK-8241478:
    vmTestbase/gc/gctests/Steal/steal001/steal001.java fails
    with OOME

  + JDK-8241574: Shenandoah: remove
    ShenandoahAssertToSpaceClosure

  + JDK-8241750: x86_32 build failure after JDK-8227269

  + JDK-8242184: CRL generation error with RSASSA-PSS

  + JDK-8242283: Can't start JVM when java home path
    includes non-ASCII character

  + JDK-8242556: Cannot load RSASSA-PSS public key with
    non-null params from byte array

  + JDK-8243029: Rewrite javax/net/ssl/compatibility/
    /Compatibility.java with a flexible interop test
    framework

  + JDK-8243138: Enhance BaseLdapServer to support starttls
    extended request

  + JDK-8243320: Add SSL root certificates to Oracle Root CA
    program

  + JDK-8243321: Add Entrust root CA - G4 to Oracle Root CA
    program

  + JDK-8243389: enhance os::pd_print_cpu_info on linux

  + JDK-8243453: java --describe-module failed with
    non-ASCII module name under non-UTF8 environment

  + JDK-8243470: [macos] bring back O2 opt level for
    unsafe.cpp

  + JDK-8243489: Thread CPU Load event may contain wrong
    data for CPU time under certain conditions

  + JDK-8243925: Toolkit#getScreenInsets() returns wrong
    value on HiDPI screens (Windows)

  + JDK-8244087: 2020-04-24 public suffix list update

  + JDK-8244151: Update MUSCLE PC/SC-Lite headers to the
    latest release 1.8.26

  + JDK-8244164: AArch64: jaotc generates incorrect code for
    compressed OOPs with non-zero heap base

  + JDK-8244196: adjust output in os_linux

  + JDK-8244225: stringop-overflow warning on strncpy call
    from compile_the_world_in

  + JDK-8244287: JFR: Methods samples have line number 0

  + JDK-8244703: 'platform encoding not initialized'
    exceptions with debugger, JNI

  + JDK-8244719: CTW: C2 compilation fails with
    'assert(!VerifyHashTableKeys || _hash_lock == 0) failed:
    remove node from hash table before modifying it'

  + JDK-8244729: Shenandoah: remove resolve paths from
    SBSA::generate_shenandoah_lrb

  + JDK-8244763: Update --release 8 symbol information after
    JSR 337 MR3

  + JDK-8244818: Java2D Queue Flusher crash while moving
    application window to external monitor

  + JDK-8245151: jarsigner should not raise duplicate
    warnings on verification

  + JDK-8245616: Bump update version for OpenJDK: jdk-11.0.9

  + JDK-8245714: 'Bad graph detected in build_loop_late'
    when loads are pinned on loop limit check uncommon
    branch

  + JDK-8245801: StressRecompilation triggers assert
    'redundunt OSR recompilation detected. memory leak in
    CodeCache!'

  + JDK-8245832: JDK build make-static-libs should build all
    JDK libraries

  + JDK-8245880: Shenandoah: check class unloading flag
    early in concurrent code root scan

  + JDK-8245981: Upgrade to jQuery 3.5.1

  + JDK-8246027: Minimal fastdebug build broken after
    JDK-8245801

  + JDK-8246094: [macos] Sound Recording and playback is not
    working

  + JDK-8246153: TestEliminateArrayCopy fails with

    -XX:+StressReflectiveCode

  + JDK-8246193: Possible NPE in ENC-PA-REP search in AS-REQ

  + JDK-8246196:
    javax/management/MBeanServer/OldMBeanServerTest fails
    with AssertionError

  + JDK-8246203: Segmentation fault in verification due to
    stack overflow with -XX:+VerifyIterativeGVN

  + JDK-8246330: Add TLS Tests for Legacy ECDSA curves

  + JDK-8246453: TestClone crashes with 'all collected
    exceptions must come from the same place'

  + JDK-8247246: Add explicit ResolvedJavaType.link and
    expose presence of default methods

  + JDK-8247350: [aarch64] assert(false) failed: wrong size
    of mach node

  + JDK-8247502: PhaseStringOpts crashes while optimising
    effectively dead code

  + JDK-8247615: Initialize the bytes left for the heap
    sampler

  + JDK-8247824: CTW: C2 (Shenandoah) compilation fails with
    SEGV in SBC2Support::pin_and_expand

  + JDK-8247874: Replacement in VersionProps.java.template
    not working when --with-vendor-bug-url contains '&'

  + JDK-8247979: aarch64: missing side effect of killing
    flags for clearArray_reg_reg

  + JDK-8248214: Add paddings for TaskQueueSuper to reduce
    false-sharing cache contention

  + JDK-8248219: aarch64: missing memory barrier in
    fast_storefield and fast_accessfield

  + JDK-8248348: Regression caused by the update to BCEL 6.0

  + JDK-8248385: [testbug][11u] Adapt TestInitiExceptions to
    jtreg 5.1

  + JDK-8248495: [macos] zerovm is broken due to libffi
    headers location

  + JDK-8248851: CMS: Missing memory fences between free
    chunk check and klass read

  + JDK-8248987: AOT's Linker.java seems to eagerly
    fail-fast on Windows

  + JDK-8249159: Downport test rework for SSLSocketTemplate
    from 8224650

  + JDK-8249215: JFrame::setVisible crashed with

    -Dfile.encoding=UTF-8 on Japanese Windows.

  + JDK-8249251: [dark_mode ubuntu 20.04] The selected menu
    is not highlighted in GTKLookAndFeel

  + JDK-8249255: Build fails if source code in cygwin home
    dir

  + JDK-8249277: TestVerifyIterativeGVN.java is failing with
    timeout in OpenJDK 11

  + JDK-8249278: Revert JDK-8226253 which breaks the spec of
    AccessibleState.SHOWING for JList

  + JDK-8249560: Shenandoah: Fix racy GC request handling

  + JDK-8249801: Shenandoah: Clear soft-refs on requested GC
    cycle

  + JDK-8249953: Shenandoah: gc/shenandoah/mxbeans tests
    should account for corner cases

  + JDK-8250582: Revert Principal Name type to NT-UNKNOWN
    when requesting TGS Kerberos tickets

  + JDK-8250609: C2 crash in IfNode::fold_compares

  + JDK-8250627: Use -XX:+/-UseContainerSupport for
    enabling/disabling Java container metrics

  + JDK-8250755: Better cleanup for
    jdk/test/javax/imageio/plugins/shared/CanWriteSequence.j
    ava

  + JDK-8250787: Provider.put no longer registering aliases
    in FIPS env

  + JDK-8250826: jhsdb does not work with coredump which
    comes from Substrate VM

  + JDK-8250827: Shenandoah: needs to reset/finish
    StringTable's dead count before/after parallel walk

  + JDK-8250844: Make sure {type,obj}ArrayOopDesc accessors
    check the bounds

  + JDK-8251117: Cannot check P11Key size in P11Cipher and
    P11AEADCipher

  + JDK-8251354: Shenandoah: Fix
    jdk/jfr/tool/TestPrintJSON.java test failure

  + JDK-8251451: Shenandoah: Remark ObjectSynchronizer roots
    with I-U

  + JDK-8251469: Better cleanup for
    test/jdk/javax/imageio/SetOutput.java

  + JDK-8251487: Shenandoah: missing detail timing tracking
    for final mark cleaning phase

  + JDK-8252120: compiler/oracle/TestCompileCommand.java
    misspells 'occured'

  + JDK-8252157: JDK-8231209 11u backport breaks jmm binary
    compatibility

  + JDK-8252258: [11u] JDK-8242154 changes the default
    vendor

  + JDK-8252804: [test] Fix 'ReleaseDeflater.java' test
    after downport of 8234011

  + JDK-8253134: JMM_VERSION should remain at 0x20020000
    (JDK 10) in JDK 11

  + JDK-8253283: [11u] Test build/translations/
    /VerifyTranslations.java failing after JDK-8252258

  + JDK-8253813: Backout JDK-8244287 from 11u: it causes
    several crashes

  + Fix regression '8250861: Crash in
    MinINode::Ideal(PhaseGVN*, bool)' introduced in jdk
    11.0.9

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177943");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14779/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14781/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14782/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14792/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14796/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14797/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14798/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14803/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203359-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f615d0b");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Packagehub-Subpackages-15-SP2-2020-3359=1

SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Packagehub-Subpackages-15-SP1-2020-3359=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2020-3359=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-3359=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14792");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14803");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1/2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-11-openjdk-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-11-openjdk-debuginfo-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-11-openjdk-debugsource-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-11-openjdk-demo-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-11-openjdk-devel-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-11-openjdk-headless-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"java-11-openjdk-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"java-11-openjdk-debuginfo-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"java-11-openjdk-debugsource-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"java-11-openjdk-demo-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"java-11-openjdk-devel-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"java-11-openjdk-headless-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"java-11-openjdk-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"java-11-openjdk-debuginfo-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"java-11-openjdk-debugsource-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"java-11-openjdk-demo-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"java-11-openjdk-devel-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"java-11-openjdk-headless-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"java-11-openjdk-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"java-11-openjdk-debuginfo-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"java-11-openjdk-debugsource-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"java-11-openjdk-demo-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"java-11-openjdk-devel-11.0.9.0-3.48.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"java-11-openjdk-headless-11.0.9.0-3.48.1")) flag++;


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
