#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1107.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117974);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-14598", "CVE-2018-14599", "CVE-2018-14600");

  script_name(english:"openSUSE Security Update : libX11 (openSUSE-2018-1107)");
  script_summary(english:"Check for the openSUSE-2018-1107 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libX11 fixes the following security issues :

  - CVE-2018-14599: The function XListExtensions was
    vulnerable to an off-by-one error caused by malicious
    server responses, leading to DoS or possibly unspecified
    other impact (bsc#1102062)

  - CVE-2018-14600: The function XListExtensions interpreted
    a variable as signed instead of unsigned, resulting in
    an out-of-bounds write (of up to 128 bytes), leading to
    DoS or remote code execution (bsc#1102068)

  - CVE-2018-14598: A malicious server could have sent a
    reply in which the first string overflows, causing a
    variable to be set to NULL that will be freed later on,
    leading to DoS (segmentation fault) (bsc#1102073)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102073"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libX11 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-xcb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-xcb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-xcb1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-xcb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libX11-6-1.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libX11-6-debuginfo-1.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libX11-data-1.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libX11-debugsource-1.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libX11-devel-1.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libX11-xcb1-1.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libX11-xcb1-debuginfo-1.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libX11-6-32bit-1.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libX11-6-32bit-debuginfo-1.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libX11-devel-32bit-1.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libX11-xcb1-32bit-1.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libX11-xcb1-32bit-debuginfo-1.6.5-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libX11-6 / libX11-6-debuginfo / libX11-data / libX11-debugsource / etc");
}
