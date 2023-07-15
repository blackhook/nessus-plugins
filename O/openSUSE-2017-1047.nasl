#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1047.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103283);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5111", "CVE-2017-5112", "CVE-2017-5113", "CVE-2017-5114", "CVE-2017-5115", "CVE-2017-5116", "CVE-2017-5117", "CVE-2017-5118", "CVE-2017-5119", "CVE-2017-5120");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2017-1047)");
  script_summary(english:"Check for the openSUSE-2017-1047 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for chromium to version 61.0.3163.79 fixes several issues.

These security issues were fixed :

  - CVE-2017-5111: Use after free in PDFium (boo#1057364).

  - CVE-2017-5112: Heap buffer overflow in WebGL
    (boo#1057364).

  - CVE-2017-5113: Heap buffer overflow in Skia
    (boo#1057364).

  - CVE-2017-5114: Memory lifecycle issue in PDFium
    (boo#1057364).

  - CVE-2017-5115: Type confusion in V8 (boo#1057364).

  - CVE-2017-5116: Type confusion in V8 (boo#1057364).

  - CVE-2017-5117: Use of uninitialized value in Skia
    (boo#1057364).

  - CVE-2017-5118: Bypass of Content Security Policy in
    Blink (boo#1057364).

  - CVE-2017-5119: Use of uninitialized value in Skia
    (boo#1057364).

  - CVE-2017-5120: Potential HTTPS downgrade during redirect
    navigation (boo#1057364)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057364"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"chromedriver-61.0.3163.79-104.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromedriver-debuginfo-61.0.3163.79-104.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-61.0.3163.79-104.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-debuginfo-61.0.3163.79-104.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-debugsource-61.0.3163.79-104.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-61.0.3163.79-110.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-debuginfo-61.0.3163.79-110.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-61.0.3163.79-110.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debuginfo-61.0.3163.79-110.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debugsource-61.0.3163.79-110.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
