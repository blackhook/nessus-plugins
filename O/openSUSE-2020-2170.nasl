#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2170.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(143529);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/07");

  script_name(english:"openSUSE Security Update : java-1_8_0-openjdk (openSUSE-2020-2170)");
  script_summary(english:"Check for the openSUSE-2020-2170 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for java-1_8_0-openjdk fixes the following issues :

  - Update to version jdk8u275 (icedtea 3.17.1)

  - JDK-8214440, bsc#1179441: Fix StartTLS functionality
    that was broken in openjdk272. (bsc#1179441)

  - JDK-8223940: Private key not supported by chosen
    signature algorithm

  - JDK-8236512: PKCS11 Connection closed after
    Cipher.doFinal and NoPadding

  - JDK-8250861: Crash in MinINode::Ideal(PhaseGVN*, bool)

  - PR3815: Fix new s390 size_t issue in
    g1ConcurrentMarkObjArrayProcessor.cpp

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179441"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected java-1_8_0-openjdk packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"java-1_8_0-openjdk-1.8.0.275-lp152.2.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-1_8_0-openjdk-accessibility-1.8.0.275-lp152.2.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.275-lp152.2.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-1_8_0-openjdk-debugsource-1.8.0.275-lp152.2.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-1_8_0-openjdk-demo-1.8.0.275-lp152.2.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.275-lp152.2.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-1_8_0-openjdk-devel-1.8.0.275-lp152.2.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.275-lp152.2.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-1_8_0-openjdk-headless-1.8.0.275-lp152.2.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.275-lp152.2.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-1_8_0-openjdk-javadoc-1.8.0.275-lp152.2.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-1_8_0-openjdk-src-1.8.0.275-lp152.2.6.2") ) flag++;

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
