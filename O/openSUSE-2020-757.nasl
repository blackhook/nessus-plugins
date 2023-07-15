#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-757.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(137132);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_cve_id("CVE-2020-2754", "CVE-2020-2755", "CVE-2020-2756", "CVE-2020-2757", "CVE-2020-2767", "CVE-2020-2773", "CVE-2020-2778", "CVE-2020-2781", "CVE-2020-2800", "CVE-2020-2803", "CVE-2020-2805", "CVE-2020-2816", "CVE-2020-2830");

  script_name(english:"openSUSE Security Update : java-11-openjdk (openSUSE-2020-757)");
  script_summary(english:"Check for the openSUSE-2020-757 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for java-11-openjdk fixes the following issues :

Java was updated to jdk-11.0.7+10 (April 2020 CPU, bsc#1169511).

Security issues fixed :

  - CVE-2020-2754: Fixed an incorrect handling of regular
    expressions that could have resulted in denial of
    service (bsc#1169511).

  - CVE-2020-2755: Fixed an incorrect handling of regular
    expressions that could have resulted in denial of
    service (bsc#1169511).

  - CVE-2020-2756: Fixed an incorrect handling of regular
    expressions that could have resulted in denial of
    service (bsc#1169511).

  - CVE-2020-2757: Fixed an object deserialization issue
    that could have resulted in denial of service via
    crafted serialized input (bsc#1169511).

  - CVE-2020-2767: Fixed an incorrect handling of
    certificate messages during TLS handshakes
    (bsc#1169511).

  - CVE-2020-2773: Fixed the incorrect handling of
    exceptions thrown by unmarshalKeyInfo() and
    unmarshalXMLSignature() (bsc#1169511).

  - CVE-2020-2778: Fixed the incorrect handling of
    SSLParameters in setAlgorithmConstraints(), which could
    have been abused to override the defined systems
    security policy and lead to the use of weak crypto
    algorithms (bsc#1169511).

  - CVE-2020-2781: Fixed the incorrect re-use of single null
    TLS sessions (bsc#1169511).

  - CVE-2020-2800: Fixed an HTTP header injection issue
    caused by mishandling of CR/LF in header values
    (bsc#1169511).

  - CVE-2020-2803: Fixed a boundary check and type check
    issue that could have led to a sandbox bypass
    (bsc#1169511).

  - CVE-2020-2805: Fixed a boundary check and type check
    issue that could have led to a sandbox bypass
    (bsc#1169511).

  - CVE-2020-2816: Fixed an incorrect handling of
    application data packets during TLS handshakes
    (bsc#1169511).

  - CVE-2020-2830: Fixed an incorrect handling of regular
    expressions that could have resulted in denial of
    service (bsc#1169511).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169511"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected java-11-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2800");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-accessibility-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-11.0.7.0-lp151.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-accessibility-11.0.7.0-lp151.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-accessibility-debuginfo-11.0.7.0-lp151.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-debuginfo-11.0.7.0-lp151.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-debugsource-11.0.7.0-lp151.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-demo-11.0.7.0-lp151.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-devel-11.0.7.0-lp151.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-headless-11.0.7.0-lp151.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-javadoc-11.0.7.0-lp151.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-jmods-11.0.7.0-lp151.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-src-11.0.7.0-lp151.3.16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-11-openjdk / java-11-openjdk-accessibility / etc");
}
