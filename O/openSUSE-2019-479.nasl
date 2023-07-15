#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-479.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123197);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-2790", "CVE-2018-2794", "CVE-2018-2795", "CVE-2018-2796", "CVE-2018-2797", "CVE-2018-2798", "CVE-2018-2799", "CVE-2018-2800", "CVE-2018-2814", "CVE-2018-2815");

  script_name(english:"openSUSE Security Update : java-1_8_0-openjdk (openSUSE-2019-479)");
  script_summary(english:"Check for the openSUSE-2019-479 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for java-1_8_0-openjdk to version 8u171 fixes the
following issues :

These security issues were fixed :

  - S8180881: Better packaging of deserialization

  - S8182362: Update CipherOutputStream Usage

  - S8183032: Upgrade to LittleCMS 2.9

  - S8189123: More consistent classloading

  - S8189969, CVE-2018-2790, bsc#1090023: Manifest better
    manifest entries

  - S8189977, CVE-2018-2795, bsc#1090025: Improve permission
    portability

  - S8189981, CVE-2018-2796, bsc#1090026: Improve queuing
    portability

  - S8189985, CVE-2018-2797, bsc#1090027: Improve tabular
    data portability

  - S8189989, CVE-2018-2798, bsc#1090028: Improve container
    portability

  - S8189993, CVE-2018-2799, bsc#1090029: Improve document
    portability

  - S8189997, CVE-2018-2794, bsc#1090024: Enhance keystore
    mechanisms

  - S8190478: Improved interface method selection

  - S8190877: Better handling of abstract classes

  - S8191696: Better mouse positioning

  - S8192025, CVE-2018-2814, bsc#1090032: Less referential
    references

  - S8192030: Better MTSchema support

  - S8192757, CVE-2018-2815, bsc#1090033: Improve stub
    classes implementation

  - S8193409: Improve AES supporting classes

  - S8193414: Improvements in MethodType lookups

  - S8193833, CVE-2018-2800, bsc#1090030: Better RMI
    connection support

For other changes please consult the changelog.

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090033"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected java-1_8_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-1.8.0.171-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-accessibility-1.8.0.171-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.171-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-debugsource-1.8.0.171-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-demo-1.8.0.171-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.171-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-devel-1.8.0.171-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.171-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-headless-1.8.0.171-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.171-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-javadoc-1.8.0.171-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-src-1.8.0.171-lp150.2.3.1") ) flag++;

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
