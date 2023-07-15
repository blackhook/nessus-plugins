#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-954.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102621);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10078", "CVE-2017-10081", "CVE-2017-10086", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10105", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10111", "CVE-2017-10114", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10118", "CVE-2017-10125", "CVE-2017-10135", "CVE-2017-10176", "CVE-2017-10193", "CVE-2017-10198", "CVE-2017-10243");

  script_name(english:"openSUSE Security Update : java-1_8_0-openjdk (openSUSE-2017-954)");
  script_summary(english:"Check for the openSUSE-2017-954 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This java-1_8_0-openjdk update to version jdk8u141 (icedtea 3.5.0)
fixes the following issues :

Security issues fixed :

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
    subcomponent JAX-WS (bsc#1049332)

Bug fixes :

  - Check registry registration location

  - Improved certificate processing

  - JMX diagnostic improvements

  - Update to libpng 1.6.28

  - Import of OpenJDK 8 u141 build 15 (bsc#1049302)

New features :

  - Support using RSAandMGF1 with the SHA hash algorithms in
    the PKCS11 provider

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049329"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049332"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_8_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/21");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-1.8.0.144-10.13.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-accessibility-1.8.0.144-10.13.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.144-10.13.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-debugsource-1.8.0.144-10.13.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-demo-1.8.0.144-10.13.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.144-10.13.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-devel-1.8.0.144-10.13.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.144-10.13.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-headless-1.8.0.144-10.13.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.144-10.13.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-javadoc-1.8.0.144-10.13.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-src-1.8.0.144-10.13.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-1.8.0.144-13.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-accessibility-1.8.0.144-13.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.144-13.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-debugsource-1.8.0.144-13.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-demo-1.8.0.144-13.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.144-13.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-devel-1.8.0.144-13.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.144-13.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-headless-1.8.0.144-13.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.144-13.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-javadoc-1.8.0.144-13.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-src-1.8.0.144-13.3") ) flag++;

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
