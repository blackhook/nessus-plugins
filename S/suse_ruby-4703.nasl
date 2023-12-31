#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ruby-4703.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(28328);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-5162", "CVE-2007-5770");

  script_name(english:"openSUSE 10 Security Update : ruby (ruby-4703)");
  script_summary(english:"Check for the ruby-4703 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of ruby improves the SSL certificate verification process.
(CVE-2007-5162, CVE-2007-5770) Prior to this update it was possible to
intercept SSL traffic with a man-in-the-middle attack."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-doc-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-test-suite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"ruby-1.8.4-17.16") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"ruby-devel-1.8.4-17.16") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"ruby-doc-html-1.8.4-17.16") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"ruby-doc-ri-1.8.4-17.16") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"ruby-examples-1.8.4-17.16") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"ruby-test-suite-1.8.4-17.16") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"ruby-tk-1.8.4-17.16") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ruby-1.8.5-23") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ruby-devel-1.8.5-23") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ruby-doc-html-1.8.5-23") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ruby-doc-ri-1.8.5-23") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ruby-examples-1.8.5-23") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ruby-test-suite-1.8.5-23") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ruby-tk-1.8.5-23") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-1.8.6.p36-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-devel-1.8.6.p36-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-doc-html-1.8.6.p36-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-doc-ri-1.8.6.p36-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-examples-1.8.6.p36-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-test-suite-1.8.6.p36-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-tk-1.8.6.p36-20.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby");
}
