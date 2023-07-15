#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1120.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103660);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-13738", "CVE-2017-13739", "CVE-2017-13740", "CVE-2017-13741", "CVE-2017-13743", "CVE-2017-13744");

  script_name(english:"openSUSE Security Update : liblouis (openSUSE-2017-1120)");
  script_summary(english:"Check for the openSUSE-2017-1120 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for liblouis fixes several issues.

These security issues were fixed :

  - CVE-2017-13738: Prevent illegal address access in the
    _lou_getALine function that allowed to cause remote DoS
    (bsc#1056105).

  - CVE-2017-13739: Prevent heap-based buffer overflow in
    the function resolveSubtable() that could have caused
    DoS or remote code execution (bsc#1056101).

  - CVE-2017-13740: Prevent stack-based buffer overflow in
    the function parseChars() that could have caused DoS or
    possibly unspecified other impact (bsc#1056097) 

  - CVE-2017-13741: Prevent use-after-free in function
    compileBrailleIndicator() that allowed to cause remote
    DoS (bsc#1056095).

  - CVE_2017-13742: Prevent stack-based buffer overflow in
    function includeFile that allowed to cause remote DoS
    (bsc#1056093).

  - CVE-2017-13743: Prevent buffer overflow triggered in the
    function _lou_showString() that allowed to cause remote
    DoS (bsc#1056090).

  - CVE-2017-13744: Prevent illegal address access in the
    function _lou_getALine() that allowed to cause remote
    DoS (bsc#1056088).

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056105"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected liblouis packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-louis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/04");
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

if ( rpm_check(release:"SUSE42.2", reference:"liblouis-data-2.6.4-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"liblouis-debugsource-2.6.4-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"liblouis-devel-2.6.4-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"liblouis-tools-2.6.4-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"liblouis-tools-debuginfo-2.6.4-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"liblouis9-2.6.4-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"liblouis9-debuginfo-2.6.4-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-louis-2.6.4-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"liblouis-data-2.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"liblouis-debugsource-2.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"liblouis-devel-2.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"liblouis-tools-2.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"liblouis-tools-debuginfo-2.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"liblouis9-2.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"liblouis9-debuginfo-2.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-louis-2.6.4-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "liblouis-data / liblouis-debugsource / liblouis-devel / etc");
}
