#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-42.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121151);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-13785", "CVE-2018-16435", "CVE-2018-2938", "CVE-2018-2940", "CVE-2018-2952", "CVE-2018-2973", "CVE-2018-3136", "CVE-2018-3139", "CVE-2018-3149", "CVE-2018-3169", "CVE-2018-3180", "CVE-2018-3214", "CVE-2018-3639");

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-2019-42) (Spectre)");
  script_summary(english:"Check for the openSUSE-2019-42 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_7_0-openjdk to version 7u201 fixes the
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

  - CVE-2018-16435: heap-based buffer overflow in SetData
    function in cmsIT8LoadFromFile

  - CVE-2018-2938: Support Derby connections (bsc#1101644)

  - CVE-2018-2940: Better stack walking (bsc#1101645)

  - CVE-2018-2952: Exception to Pattern Syntax (bsc#1101651)

  - CVE-2018-2973: Improve LDAP support (bsc#1101656)

  - CVE-2018-3639 cpu speculative store bypass mitigation

This update was imported from the SUSE:SLE-12:Update update project."
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112153"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_7_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3180");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/14");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-accessibility-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-bootstrap-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-bootstrap-debuginfo-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-bootstrap-debugsource-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-bootstrap-devel-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-bootstrap-devel-debuginfo-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-bootstrap-headless-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-bootstrap-headless-debuginfo-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-debugsource-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-demo-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-devel-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-headless-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-javadoc-1.7.0.201-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_7_0-openjdk-src-1.7.0.201-54.1") ) flag++;

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
