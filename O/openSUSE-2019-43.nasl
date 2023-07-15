#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-43.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121152);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-13785", "CVE-2018-16435", "CVE-2018-3136", "CVE-2018-3139", "CVE-2018-3149", "CVE-2018-3169", "CVE-2018-3180", "CVE-2018-3183", "CVE-2018-3214");

  script_name(english:"openSUSE Security Update : java-1_8_0-openjdk (openSUSE-2019-43)");
  script_summary(english:"Check for the openSUSE-2019-43 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for java-1_8_0-openjdk to version 8u191 fixes the
following issues :

Security issues fixed :

  - CVE-2018-3136: Manifest better support (bsc#1112142)

  - CVE-2018-3139: Better HTTP Redirection (bsc#1112143)

  - CVE-2018-3149: Enhance JNDI lookups (bsc#1112144)

  - CVE-2018-3169: Improve field accesses (bsc#1112146)

  - CVE-2018-3180: Improve TLS connections stability
    (bsc#1112147)

  - CVE-2018-3214: Better RIFF reading support (bsc#1112152)

  - CVE-2018-13785: Upgrade JDK 8u to libpng 1.6.35
    (bsc#1112153)

  - CVE-2018-3183: Improve script engine support
    (bsc#1112148)

  - CVE-2018-16435: heap-based buffer overflow in SetData
    function in cmsIT8LoadFromFile

This update was imported from the SUSE:SLE-15:Update update project."
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112153"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected java-1_8_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/14");
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

if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-1.8.0.191-lp150.2.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-accessibility-1.8.0.191-lp150.2.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.191-lp150.2.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-debugsource-1.8.0.191-lp150.2.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-demo-1.8.0.191-lp150.2.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.191-lp150.2.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-devel-1.8.0.191-lp150.2.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.191-lp150.2.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-headless-1.8.0.191-lp150.2.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.191-lp150.2.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-javadoc-1.8.0.191-lp150.2.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-1_8_0-openjdk-src-1.8.0.191-lp150.2.9.2") ) flag++;

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
