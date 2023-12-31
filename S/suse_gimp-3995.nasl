#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update gimp-3995.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27237);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-4519");

  script_name(english:"openSUSE 10 Security Update : gimp (gimp-3995)");
  script_summary(english:"Check for the gimp-3995 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple gimp import filters contained integer overflows. Attackers
could exploit that to potentially execute code by tricking users into
opening specially crafted files (CVE-2006-4519)."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gimp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-unstable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-unstable-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"gimp-2.2.10-22.29") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"gimp-devel-2.2.10-22.29") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"gimp-unstable-2.3.7-17.9") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"gimp-unstable-devel-2.3.7-17.9") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"gimp-2.2.13-35") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"gimp-devel-2.2.13-35") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"gimp-unstable-2.3.11-51.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"gimp-unstable-devel-2.3.11-51.5") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp / gimp-devel / gimp-unstable / gimp-unstable-devel");
}
