#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-444.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84385);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-0848", "CVE-2015-4588");

  script_name(english:"openSUSE Security Update : libwmf (openSUSE-2015-444)");
  script_summary(english:"Check for the openSUSE-2015-444 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libwmf was updated to fix two security issues.

The following vulnerabilities were fixed :

  - CVE-2015-0848: An attacker that could trick a victim
    into opening a specially crafted WMF file with BMP
    portions in a libwmf based application could have
    executed arbitrary code with the user's privileges.
    (boo#933109)

  - CVE-2015-0848: An attacker that could trick a victim
    into opening a specially crafted WMF file in a libwmf
    based application could have executed arbitrary code
    through incorrect run-length encoding. (boo#933109)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=933109"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libwmf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwmf-0_2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwmf-0_2-7-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwmf-0_2-7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwmf-0_2-7-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwmf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwmf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwmf-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwmf-gnome-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwmf-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwmf-gnome-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwmf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwmf-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/25");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libwmf-0_2-7-0.2.8.4-239.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwmf-0_2-7-debuginfo-0.2.8.4-239.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwmf-debugsource-0.2.8.4-239.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwmf-devel-0.2.8.4-239.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwmf-gnome-0.2.8.4-239.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwmf-gnome-debuginfo-0.2.8.4-239.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwmf-tools-0.2.8.4-239.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwmf-tools-debuginfo-0.2.8.4-239.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libwmf-0_2-7-32bit-0.2.8.4-239.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libwmf-0_2-7-debuginfo-32bit-0.2.8.4-239.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libwmf-gnome-32bit-0.2.8.4-239.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libwmf-gnome-debuginfo-32bit-0.2.8.4-239.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwmf-0_2-7 / libwmf-0_2-7-32bit / libwmf-0_2-7-debuginfo / etc");
}
