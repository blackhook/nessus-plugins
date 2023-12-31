#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-416.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84137);
  script_version("2.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : tidy (openSUSE-2015-416)");
  script_summary(english:"Check for the openSUSE-2015-416 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tidy was updated to fix one security issue.

The following vulnerability was fixed :

  - A heap-based buffer overflow in tidy could have
    unspecified impact when processing user-supplied input."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=933588"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tidy packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtidy-0_99-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtidy-0_99-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtidy-0_99-0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tidy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tidy-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/12");
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

if ( rpm_check(release:"SUSE13.1", reference:"libtidy-0_99-0-1.0.20100204cvs-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtidy-0_99-0-debuginfo-1.0.20100204cvs-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libtidy-0_99-0-devel-1.0.20100204cvs-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tidy-1.0.20100204cvs-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tidy-debuginfo-1.0.20100204cvs-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tidy-debugsource-1.0.20100204cvs-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtidy-0_99-0-1.0.20100204cvs-19.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtidy-0_99-0-debuginfo-1.0.20100204cvs-19.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtidy-0_99-0-devel-1.0.20100204cvs-19.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"tidy-1.0.20100204cvs-19.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"tidy-debuginfo-1.0.20100204cvs-19.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"tidy-debugsource-1.0.20100204cvs-19.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtidy-0_99-0 / libtidy-0_99-0-debuginfo / libtidy-0_99-0-devel / etc");
}
