#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-904.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87446);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-8126");

  script_name(english:"openSUSE Security Update : libpng16 (openSUSE-2015-904)");
  script_summary(english:"Check for the openSUSE-2015-904 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libpng16 was updated to fix one security issue.

The following vulnerability was fixed :

  - CVE-2015-8126: previously fixed incompletely
    [boo#954980]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954980"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpng16 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-16-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-16-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-16-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-compat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-compat-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpng16-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/17");
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

if ( rpm_check(release:"SUSE13.1", reference:"libpng16-16-1.6.6-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpng16-16-debuginfo-1.6.6-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpng16-compat-devel-1.6.6-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpng16-debugsource-1.6.6-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpng16-devel-1.6.6-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpng16-tools-1.6.6-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpng16-tools-debuginfo-1.6.6-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpng16-16-32bit-1.6.6-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpng16-16-debuginfo-32bit-1.6.6-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpng16-compat-devel-32bit-1.6.6-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpng16-devel-32bit-1.6.6-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpng16-16-1.6.13-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpng16-16-debuginfo-1.6.13-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpng16-compat-devel-1.6.13-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpng16-debugsource-1.6.13-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpng16-devel-1.6.13-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpng16-tools-1.6.13-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpng16-tools-debuginfo-1.6.13-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpng16-16-32bit-1.6.13-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpng16-16-debuginfo-32bit-1.6.13-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpng16-compat-devel-32bit-1.6.13-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpng16-devel-32bit-1.6.13-2.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng16-16 / libpng16-16-32bit / libpng16-16-debuginfo / etc");
}
