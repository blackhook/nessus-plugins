#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-999.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102969);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-12927", "CVE-2017-12978");

  script_name(english:"openSUSE Security Update : cacti / cacti-spine (openSUSE-2017-999)");
  script_summary(english:"Check for the openSUSE-2017-999 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for cacti and cacti-spine fixes security issues and bugs.

The following vulnerabilities were fixed :

  - CVE-2017-12927: Cross-site scripting vulnerability in
    methodparameter (bsc#1054390)

  - CVE-2017-12978:Cross-site scripting vulnerability via
    the title field (bsc#1054742) It also contains all
    upstream bug fixes and improvements in the 1.1.18
    release :

  - Sort devices by polling time to allow long running d

  - Allow user to hide Graphs from disabled Devices

  - Create a separate Realm for Realtime Graphs

  - Fix various JavaScript errors

  - updated translations

  - Can now export Device table results to CSV

  - Allow Log Rotation to be other than Daily, and other log
    rotation improvements"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054742"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cacti / cacti-spine packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/06");
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

if ( rpm_check(release:"SUSE42.2", reference:"cacti-1.1.19-16.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"cacti-spine-1.1.19-7.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"cacti-spine-debuginfo-1.1.19-7.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"cacti-spine-debugsource-1.1.19-7.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cacti-1.1.19-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cacti-spine-1.1.19-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cacti-spine-debuginfo-1.1.19-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cacti-spine-debugsource-1.1.19-13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cacti-spine / cacti-spine-debuginfo / cacti-spine-debugsource / etc");
}
