#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1365.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105245);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-17459");

  script_name(english:"openSUSE Security Update : fossil (openSUSE-2017-1365)");
  script_summary(english:"Check for the openSUSE-2017-1365 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for fossil to version 2.4 fixes the following issues :

  - CVE-2017-17459: Client-side code execution via crafted
    'ssh://' URLs (bsc#1071709)

The impact of this vulnerability is more limited than similar vectors
fixed in other SCMs, as there is no known way to mask the repository
URL or otherwise trigger non-interactively.

This update also contains all bug fixes and improvements in the 2.4
release :

  - URL Aliases

  - tech-note search capability

  - Various added command line options

  - Annation depth is now configurable

The following legacy options are no longer available :

  - --no-dir-symlinks option

  - legacy configuration sync protocol"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071709"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected fossil packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fossil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fossil-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fossil-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");
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

if ( rpm_check(release:"SUSE42.2", reference:"fossil-2.4-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"fossil-debuginfo-2.4-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"fossil-debugsource-2.4-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"fossil-2.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"fossil-debuginfo-2.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"fossil-debugsource-2.4-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fossil / fossil-debuginfo / fossil-debugsource");
}
