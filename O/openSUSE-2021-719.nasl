#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-719.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149567);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2021-2161", "CVE-2021-2163");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"openSUSE Security Update : java-11-openjdk (openSUSE-2021-719)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for java-11-openjdk fixes the following issues :

  - Update to upstream tag jdk-11.0.11+9 (April 2021 CPU)

  - CVE-2021-2163: Fixed incomplete enforcement of JAR
    signing disabled algorithms (bsc#1185055)

  - CVE-2021-2161: Fixed incorrect handling of partially
    quoted arguments in ProcessBuilder (bsc#1185056)

  - moved mozilla-nss dependency to java-11-openjdk-headless
    package, this is necessary to be able to do crypto with
    just java-11-openjdk-headless installed (bsc#1184606).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185056");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-11-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.2", reference:"java-11-openjdk-11.0.11.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-11-openjdk-accessibility-11.0.11.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-11-openjdk-accessibility-debuginfo-11.0.11.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-11-openjdk-debuginfo-11.0.11.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-11-openjdk-debugsource-11.0.11.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-11-openjdk-demo-11.0.11.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-11-openjdk-devel-11.0.11.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-11-openjdk-headless-11.0.11.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-11-openjdk-javadoc-11.0.11.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-11-openjdk-jmods-11.0.11.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"java-11-openjdk-src-11.0.11.0-lp152.2.12.1") ) flag++;

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
