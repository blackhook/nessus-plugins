#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1138.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117986);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-2938", "CVE-2018-2940", "CVE-2018-2952", "CVE-2018-2973");

  script_name(english:"openSUSE Security Update : java-1_8_0-openjdk (openSUSE-2018-1138)");
  script_summary(english:"Check for the openSUSE-2018-1138 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_8_0-openjdk to the jdk8u181 (icedtea 3.9.0)
release fixes the following issues :

These security issues were fixed :

  - CVE-2018-2938: Difficult to exploit vulnerability
    allowed unauthenticated attacker with network access via
    multiple protocols to compromise Java SE. Successful
    attacks of this vulnerability can result in takeover of
    Java SE (bsc#1101644).

  - CVE-2018-2940: Vulnerability in subcomponent: Libraries.
    Easily exploitable vulnerability allowed unauthenticated
    attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks
    require human interaction from a person other than the
    attacker. Successful attacks of this vulnerability can
    result in unauthorized read access to a subset of Java
    SE, Java SE Embedded accessible data (bsc#1101645)

  - CVE-2018-2952: Vulnerability in subcomponent:
    Concurrency. Difficult to exploit vulnerability allowed
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded, JRockit (bsc#1101651)

  - CVE-2018-2973: Vulnerability in subcomponent: JSSE.
    Difficult to exploit vulnerability allowed
    unauthenticated attacker with network access via SSL/TLS
    to compromise Java SE, Java SE Embedded. Successful
    attacks of this vulnerability can result in unauthorized
    creation, deletion or modification access to critical
    data or all Java SE, Java SE Embedded accessible data
    (bsc#1101656)

These non-security issues were fixed :

  - Improve desktop file usage

  - Better Internet address support

  - speculative traps break when classes are redefined

  - sun/security/pkcs11/ec/ReadCertificates.java fails
    intermittently

  - Clean up code that saves the previous versions of
    redefined classes

  - Prevent SIGSEGV in
    ReceiverTypeData::clean_weak_klass_links

  - RedefineClasses() tests fail
    assert(((Metadata*)obj)->is_valid()) failed: obj is
    valid

  - NMT is not enabled if NMT option is specified after
    class path specifiers

  - EndEntityChecker should not process custom extensions
    after PKIX validation

  - SupportedDSAParamGen.java failed with timeout

  - Montgomery multiply intrinsic should use correct name

  - When determining the ciphersuite lists, there is no
    debug output for disabled suites.

  - sun/security/mscapi/SignedObjectChain.java fails on
    Windows

  - On Windows Swing changes keyboard layout on a window
    activation

  - IfNode::range_check_trap_proj() should handler dying
    subgraph with single if proj

  - Even better Internet address support

  - Newlines in JAXB string values of SOAP-requests are
    escaped to ' '

  - TestFlushableGZIPOutputStream failing with
    IndexOutOfBoundsException

  - Unable to use JDWP API in JDK 8 to debug JDK 9 VM

  - Hotspot crash on Cassandra 3.11.1 startup with libnuma
    2.0.3

  - Performance drop with Java JDK 1.8.0_162-b32

  - Upgrade time-zone data to tzdata2018d

  - Fix potential crash in BufImg_SetupICM

  - JDK 8u181 l10n resource file update

  - Remove debug print statements from RMI fix

  - (tz) Upgrade time-zone data to tzdata2018e

  - ObjectInputStream filterCheck method throws
    NullPointerException

  - adjust reflective access checks

  - Fixed builds on s390 (bsc#1106812)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106812"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_8_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-1.8.0.181-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-accessibility-1.8.0.181-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.181-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-debugsource-1.8.0.181-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-demo-1.8.0.181-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.181-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-devel-1.8.0.181-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.181-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-headless-1.8.0.181-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.181-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-javadoc-1.8.0.181-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-src-1.8.0.181-lp150.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_8_0-openjdk / java-1_8_0-openjdk-accessibility / etc");
}
