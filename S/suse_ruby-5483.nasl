#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ruby-5483.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34028);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-1145", "CVE-2008-1891", "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726", "CVE-2008-2728");

  script_name(english:"openSUSE 10 Security Update : ruby (ruby-5483)");
  script_summary(english:"Check for the ruby-5483 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of ruby fixes :

  - a possible information leakage (CVE-2008-1145) 

  - a directory traversal bug (CVE-2008-1891) in WEBrick 

  - various memory corruptions and integer overflows in
    array and string handling (CVE-2008-2662, CVE-2008-2663,
    CVE-2008-2664, CVE-2008-2725, CVE-2008-2726,
    CVE-2008-2727, CVE-2008-2728)"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(22, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-doc-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-test-suite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"ruby-1.8.5-25") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ruby-devel-1.8.5-25") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ruby-doc-html-1.8.5-25") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ruby-doc-ri-1.8.5-25") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ruby-examples-1.8.5-25") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ruby-test-suite-1.8.5-25") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ruby-tk-1.8.5-25") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-1.8.6.p36-20.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-devel-1.8.6.p36-20.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-doc-html-1.8.6.p36-20.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-doc-ri-1.8.6.p36-20.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-examples-1.8.6.p36-20.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-test-suite-1.8.6.p36-20.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-tk-1.8.6.p36-20.4") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby");
}