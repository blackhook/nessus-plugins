#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-297.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82654);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-7437");

  script_name(english:"openSUSE Security Update : potrace (openSUSE-2015-297)");
  script_summary(english:"Check for the openSUSE-2015-297 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The bitmap to vector graphic tracing utility potrace was updated to
fix one security issue.

The following vulnerability was fixed :

  - Very large bitmaps could trigger a buffer overflow,
    crashing the program and causing denial of service
    (bsc#924904, CVE-2013-7437)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=924904"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected potrace packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpotrace0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpotrace0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:potrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:potrace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:potrace-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:potrace-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libpotrace0-1.11-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpotrace0-debuginfo-1.11-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"potrace-1.11-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"potrace-debuginfo-1.11-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"potrace-debugsource-1.11-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"potrace-devel-1.11-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpotrace0-1.11-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpotrace0-debuginfo-1.11-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"potrace-1.11-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"potrace-debuginfo-1.11-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"potrace-debugsource-1.11-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"potrace-devel-1.11-4.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpotrace0 / libpotrace0-debuginfo / potrace / potrace-debuginfo / etc");
}
