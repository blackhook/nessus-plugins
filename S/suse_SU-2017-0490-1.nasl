#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0490-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97296);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2016-2183", "CVE-2016-5546", "CVE-2016-5547", "CVE-2016-5548", "CVE-2016-5549", "CVE-2016-5552", "CVE-2017-3231", "CVE-2017-3241", "CVE-2017-3252", "CVE-2017-3253", "CVE-2017-3259", "CVE-2017-3260", "CVE-2017-3261", "CVE-2017-3272", "CVE-2017-3289");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : java-1_7_0-openjdk (SUSE-SU-2017:0490-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_7_0-openjdk fixes the following issues :

  - Oracle Critical Patch Update of January 2017 to OpenJDK
    7u131 (bsc#1020905) :

  - Security Fixes

  - S8138725: Add options for Javadoc generation

  - S8140353: Improve signature checking

  - S8151934, CVE-2017-3231: Resolve class resolution

  - S8156804, CVE-2017-3241: Better constraint checking

  - S8158406: Limited Parameter Processing

  - S8158997: JNDI Protocols Switch

  - S8159507: RuntimeVisibleAnnotation validation

  - S8161218: Better bytecode loading

  - S8161743, CVE-2017-3252: Provide proper login context

  - S8162577: Standardize logging levels

  - S8162973: Better component components

  - S8164143, CVE-2017-3260: Improve components for menu
    items

  - S8164147, CVE-2017-3261: Improve streaming socket output

  - S8165071, CVE-2016-2183: Expand TLS support

  - S8165344, CVE-2017-3272: Update concurrency support

  - S8166988, CVE-2017-3253: Improve image processing
    performance

  - S8167104, CVE-2017-3289: Additional class construction
    refinements

  - S8167223, CVE-2016-5552: URL handling improvements

  - S8168705, CVE-2016-5547: Better ObjectIdentifier
    validation

  - S8168714, CVE-2016-5546: Tighten ECDSA validation

  - S8168728, CVE-2016-5548: DSA signing improvments

  - S8168724, CVE-2016-5549: ECDSA signing improvments

  - S6253144: Long narrowing conversion should describe the
    algorithm used and implied 'risks'

  - S6328537: Improve javadocs for Socket class by adding
    references to SocketOptions

  - S6978886: javadoc shows stacktrace after print error
    resulting from disk full

  - S6995421: Eliminate the static dependency to
    sun.security.ec.ECKeyFactory

  - S6996372: synchronizing handshaking hash

  - S7027045: (doc) java/awt/Window.java has several typos
    in javadoc

  - S7054969: Null-check-in-finally pattern in java/security
    documentation

  - S7072353: JNDI libraries do not build with javac
    -Xlint:all -Werror

  - S7075563: Broken link in 'javax.swing.SwingWorker'

  - S7077672: jdk8_tl nightly fail in step-2 build on
    8/10/11

  - S7088502: Security libraries don't build with javac
    -Werror

  - S7092447: Clarify the default locale used in each locale
    sensitive operation

  - S7093640: Enable client-side TLS 1.2 by default

  - S7103570: AtomicIntegerFieldUpdater does not work when
    SecurityManager is installed

  - S7117360: Warnings in java.util.concurrent.atomic
    package

  - S7117465: Warning cleanup for IMF classes

  - S7187144: JavaDoc for ScriptEngineFactory.getProgram()
    contains an error

  - S8000418: javadoc should used a standard 'generated by
    javadoc' string

  - S8000666: javadoc should write directly to Writer
    instead of composing strings

  - S8000673: remove dead code from HtmlWriter and subtypes

  - S8000970: break out auxiliary classes that will prevent
    multi-core compilation of the JDK

  - S8001669: javadoc internal DocletAbortException should
    set cause when appropriate

  - S8008949: javadoc stopped copying doc-files

  - S8011402: Move blacklisting certificate logic from hard
    code to data

  - S8011547: Update XML Signature implementation to Apache
    Santuario 1.5.4

  - S8012288: XML DSig API allows wrong tag names and extra
    elements in SignedInfo

  - S8016217: More javadoc warnings

  - S8017325: Cleanup of the javadoc <code> tag in
    java.security.cert

  - S8017326: Cleanup of the javadoc <code> tag in
    java.security.spec

  - S8019772: Fix doclint issues in javax.crypto and
    javax.security subpackages

  - S8020557: javadoc cleanup in javax.security

  - S8020688: Broken links in documentation at
    http://docs.oracle.com/javase/6/docs/api/index.

  - S8021108: Clean up doclint warnings and errors in
    java.text package

  - S8021417: Fix doclint issues in java.util.concurrent

  - S8021833: javadoc cleanup in java.net

  - S8022120: JCK test
    api/javax_xml/crypto/dsig/TransformService/index_ParamMe
    thods fails

  - S8022175: Fix doclint warnings in javax.print

  - S8022406: Fix doclint issues in java.beans

  - S8022746: List of spelling errors in API doc

  - S8024779: [macosx] SwingNode crashes on exit

  - S8025085: [javadoc] some errors in javax/swing

  - S8025218: [javadoc] some errors in java/awt classes

  - S8025249: [javadoc] fix some javadoc errors in
    javax/swing/

  - S8025409: Fix javadoc comments errors and warning
    reported by doclint report

  - S8026021: more fix of javadoc errors and warnings
    reported by doclint, see the description

  - S8037099: [macosx] Remove all references to GC from
    native OBJ-C code

  - S8038184: XMLSignature throws
    StringIndexOutOfBoundsException if ID attribute value is
    empty String

  - S8038349: Signing XML with DSA throws Exception when key
    is larger than 1024 bits

  - S8049244: XML Signature performance issue caused by
    unbuffered signature data

  - S8049432: New tests for TLS property
    jdk.tls.client.protocols

  - S8050893: (smartcardio) Invert reset argument in tests
    in sun/security/smartcardio

  - S8059212: Modify regression tests so that they do not
    just fail if no cardreader found

  - S8068279: (typo in the spec)
    javax.script.ScriptEngineFactory.getLanguageName

  - S8068491: Update the protocol for references of
    docs.oracle.com to HTTPS.

  - S8069038: javax/net/ssl/TLS/TLSClientPropertyTest.java
    needs to be updated for JDK-8061210

  - S8076369: Introduce the jdk.tls.client.protocols system
    property for JDK 7u

  - S8139565: Restrict certificates with DSA keys less than
    1024 bits

  - S8140422: Add mechanism to allow non default root CAs to
    be not subject to algorithm restrictions

  - S8140587: Atomic*FieldUpdaters should use
    Class.isInstance instead of direct class check

  - S8143959: Certificates requiring blacklisting

  - S8145984: [macosx] sun.lwawt.macosx.CAccessible leaks

  - S8148516: Improve the default strength of EC in JDK

  - S8149029: Secure validation of XML based digital
    signature always enabled when checking wrapping attacks

  - S8151893: Add security property to configure XML
    Signature secure validation mode

  - S8155760: Implement Serialization Filtering

  - S8156802: Better constraint checking

  - S8161228: URL objects with custom protocol handlers have
    port changed after deserializing

  - S8161571: Verifying ECDSA signatures permits trailing
    bytes

  - S8163304: jarsigner -verbose -verify should print the
    algorithms used to sign the jar

  - S8164908: ReflectionFactory support for IIOP and custom
    serialization

  - S8165230: RMIConnection addNotificationListeners failing
    with specific inputs

  - S8166393: disabledAlgorithms property should not be
    strictly parsed

  - S8166591: [macos 10.12] Trackpad scrolling of text on OS
    X 10.12 Sierra is very fast (Trackpad, Retina only)

  - S8166739: Improve extensibility of ObjectInputFilter
    information passed to the filter

  - S8166875: (tz) Support tzdata2016g

  - S8166878: Connection reset during TLS handshake

  - S8167356: Follow up fix for jdk8 backport of 8164143.
    Changes for CMenuComponent.m were missed

  - S8167459: Add debug output for indicating if a chosen
    ciphersuite was legacy

  - S8167472: Chrome interop regression with JDK-8148516

  - S8167591: Add MD5 to signed JAR restrictions

  - S8168861: AnchorCertificates uses hard-coded password
    for cacerts keystore

  - S8168993: JDK8u121 L10n resource file update

  - S8169191: (tz) Support tzdata2016i

  - S8169688: Backout (remove) MD5 from
    jdk.jar.disabledAlgorithms for January CPU

  - S8169911: Enhanced tests for jarsigner -verbose -verify
    after JDK-8163304

  - S8170131: Certificates not being blocked by
    jdk.tls.disabledAlgorithms property

  - S8170268: 8u121 L10n resource file update - msgdrop 20

  - S8173622: Backport of 7180907 is incomplete

  - S8173849: Fix use of java.util.Base64 in test cases

  - S8173854: [TEST] Update DHEKeySizing test case following
    8076328 & 8081760

  - CVE-2017-3259 Vulnerability allows unauthenticated
    attacker with network access via multiple protocols to
    compromise Java SE.

  - Backports

  - S7102489, PR3316, RH1390708: RFE: cleanup jlong typedef
    on __APPLE__and _LLP64 systems.

  - S8000351, PR3316, RH1390708: Tenuring threshold should
    be unsigned

  - S8153711, PR3315, RH1284948: [REDO] GlobalRefs never
    deleted when processing invokeMethod command

  - S8170888, PR3316, RH1390708: [linux] support for cgroup
    memory limits in container (ie Docker) environments

  - Bug fixes

  - PR3318: Replace 'infinality' with 'improved font
    rendering' (--enable-improved-font-rendering)

  - PR3318: Fix compatibility with vanilla Fontconfig

  - PR3318: Fix glyph y advance

  - PR3318: Always round glyph advance in 26.6 space

  - PR3318: Simplify glyph advance handling

  - PR3324: Fix NSS_LIBDIR substitution in
    make_generic_profile.sh broken by PR1989

  - AArch64 port

  - S8165673, PR3320: AArch64: Fix JNI floating point
    argument handling</code></code>

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://docs.oracle.com/javase/6/docs/api/index.
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c4f4829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1020905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2183/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5546/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5547/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5548/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5549/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5552/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3231/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3241/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3252/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3253/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3259/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3260/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3261/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3272/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3289/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170490-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b905757"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12:zypper in -t patch
SUSE-SLE-SAP-12-2017-255=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-255=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-255=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-255=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2017-255=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-255=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2017-255=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/21");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-debugsource-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-demo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-devel-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-headless-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-debugsource-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-demo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-devel-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-headless-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-debugsource-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-demo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-devel-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_7_0-openjdk-debugsource-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-debugsource-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-1.7.0.131-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.131-39.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-openjdk");
}
