#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-869.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102058);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-5824", "CVE-2016-5827", "CVE-2016-9584");

  script_name(english:"openSUSE Security Update : libical (openSUSE-2017-869)");
  script_summary(english:"Check for the openSUSE-2017-869 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libical fixes the following issues :

Security issues fixed :

  - CVE-2016-5824: libical 1.0 allows remote attackers to
    cause a denial of service (use-after-free) via a crafted
    ics file. (bsc#986639)

  - CVE-2016-5827: The icaltime_from_string function in
    libical 0.47 and 1.0 allows remote attackers to cause a
    denial of service (out-of-bounds heap read) via a
    crafted string to the icalparser_parse_string function.
    (bsc#986631)

  - CVE-2016-9584: libical allows remote attackers to cause
    a denial of service (use-after-free) and possibly read
    heap memory via a crafted ics file. (bsc#1015964)

Bug fixes :

  - libical crashes while parsing timezones (bsc#1044995)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986639"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libical packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libical-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libical-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libical-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libical1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libical1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libical1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libical1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libical-debugsource-1.0.1-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libical-devel-1.0.1-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libical-devel-static-1.0.1-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libical1-1.0.1-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libical1-debuginfo-1.0.1-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libical1-32bit-1.0.1-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libical1-debuginfo-32bit-1.0.1-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libical-debugsource-1.0.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libical-devel-1.0.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libical-devel-static-1.0.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libical1-1.0.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libical1-debuginfo-1.0.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libical1-32bit-1.0.1-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libical1-debuginfo-32bit-1.0.1-16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libical-debugsource / libical-devel / libical-devel-static / etc");
}
