#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-256.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108357);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-2579", "CVE-2018-2588", "CVE-2018-2599", "CVE-2018-2602", "CVE-2018-2603", "CVE-2018-2618", "CVE-2018-2629", "CVE-2018-2633", "CVE-2018-2634", "CVE-2018-2637", "CVE-2018-2641", "CVE-2018-2663", "CVE-2018-2677", "CVE-2018-2678");

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-2018-256)");
  script_summary(english:"Check for the openSUSE-2018-256 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_7_0-openjdk fixes the following issues :

Security issues fixed in OpenJDK 7u171 (January 2018 
CPU)(bsc#1076366) :

  - CVE-2018-2579: Improve key keying case

  - CVE-2018-2588: Improve LDAP logins

  - CVE-2018-2599: Improve reliability of DNS lookups

  - CVE-2018-2602: Improve usage messages

  - CVE-2018-2603: Improve PKCS usage

  - CVE-2018-2618: Stricter key generation

  - CVE-2018-2629: Improve GSS handling

  - CVE-2018-2633: Improve LDAP lookup robustness

  - CVE-2018-2634: Improve property negotiations

  - CVE-2018-2637: Improve JMX supportive features

  - CVE-2018-2641: Improve GTK initialization

  - CVE-2018-2663: More refactoring for deserialization
    cases

  - CVE-2018-2677: More refactoring for client
    deserialization cases

  - CVE-2018-2678: More refactoring for naming

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076366"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_7_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-accessibility-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-bootstrap-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-bootstrap-debuginfo-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-bootstrap-debugsource-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-bootstrap-devel-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-bootstrap-devel-debuginfo-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-bootstrap-headless-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-bootstrap-headless-debuginfo-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-debugsource-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-demo-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-devel-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-headless-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-javadoc-1.7.0.171-48.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-src-1.7.0.171-48.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-openjdk-bootstrap / etc");
}
