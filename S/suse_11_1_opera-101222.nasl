#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update opera-3732.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53686);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-4508", "CVE-2010-4579", "CVE-2010-4580", "CVE-2010-4581", "CVE-2010-4582", "CVE-2010-4583", "CVE-2010-4584", "CVE-2010-4585", "CVE-2010-4586");

  script_name(english:"openSUSE Security Update : opera (openSUSE-SU-2010:1094-1)");
  script_summary(english:"Check for the opera-3732 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"opera 11.00 fixes among other things several security vulnerabilities.
Please refer opera's site for more information:
http://www.opera.com/docs/changelogs/unix/1100/

(CVE-2010-4508, CVE-2010-4579, CVE-2010-4580, CVE-2010-4581,
CVE-2010-4582, CVE-2010-4583, CVE-2010-4584, CVE-2010-4585,
CVE-2010-4586)"
  );
  # http://www.opera.com/docs/changelogs/unix/1100/
  script_set_attribute(
    attribute:"see_also",
    value:"https://help.opera.com/en/latest/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=659882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2010-12/msg00053.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected opera packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"opera-11.00-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"opera-gtk-11.00-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"opera-kde4-11.00-1.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opera / opera-gtk / opera-kde4");
}
