#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-108.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74544);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2011-3970");

  script_name(english:"openSUSE Security Update : libxslt (openSUSE-2012-108)");
  script_summary(english:"Check for the openSUSE-2012-108 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:"Fix crash due to out of bounds read in libxslt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746039"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxslt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"libxslt-debugsource-1.1.26-15.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libxslt-devel-1.1.26-15.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libxslt-python-1.1.26-15.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libxslt-python-debuginfo-1.1.26-15.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libxslt-python-debugsource-1.1.26-15.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libxslt1-1.1.26-15.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libxslt1-debuginfo-1.1.26-15.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libxslt-devel-32bit-1.1.26-15.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libxslt1-32bit-1.1.26-15.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libxslt1-debuginfo-32bit-1.1.26-15.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxslt-python / libxslt-python-debuginfo / etc");
}
