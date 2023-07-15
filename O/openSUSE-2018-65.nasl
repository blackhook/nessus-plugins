#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-65.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106224);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-0486");

  script_name(english:"openSUSE Security Update : xmltooling (openSUSE-2018-65)");
  script_summary(english:"Check for the openSUSE-2018-65 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xmltooling fixes the following issues :

  - CVE-2018-0486: Fixed a security bug when xmltooling
    mishandles digital signatures of user attribute data,
    which allows remote attackers to obtain sensitive
    information or conduct impersonation attacks via a
    crafted DTD (bsc#1075975)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075975"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xmltooling packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxmltooling-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxmltooling6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxmltooling6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xmltooling-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xmltooling-schemas");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libxmltooling-devel-1.5.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libxmltooling6-1.5.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libxmltooling6-debuginfo-1.5.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xmltooling-debugsource-1.5.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xmltooling-schemas-1.5.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libxmltooling-devel-1.5.6-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libxmltooling6-1.5.6-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libxmltooling6-debuginfo-1.5.6-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xmltooling-debugsource-1.5.6-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xmltooling-schemas-1.5.6-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxmltooling-devel / libxmltooling6 / libxmltooling6-debuginfo / etc");
}
