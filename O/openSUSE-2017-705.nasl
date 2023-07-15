#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-705.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100863);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-8108");

  script_name(english:"openSUSE Security Update : lynis (openSUSE-2017-705)");
  script_summary(english:"Check for the openSUSE-2017-705 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for lynis fixes the following issues :

Lynis 2.5.1 :

  - Improved detection of SSL certificate files

  - Minor changes to improve logging and results

  - Firewall tests: Determine if CSF is in testing mode

The Update also includes changes from Lynis 2.5.0 :

  - CVE-2017-8108: symlink attack may have allowed arbitrary
    file overwrite or privilege escalation (boo#1043463)

  - Deleted unused tests from database file

  - Additional sysctls are tested

  - Extended test with Symantec components

  - Snort detection

  - Snort configuration file

The update also includes Lynis 2.4.8 (Changelog from 2.4.1)

  - More PHP paths added

  - Minor changes to text

  - Show atomic test in report

  - Added FileInstalledByPackage function (dpkg and rpm
    supported)

  - Mark Arch Linux version as rolling release (instead of
    unknown)

  - Support for Manjaro Linux

  - Escape files when testing if they are readable

  - Code cleanups

  - Allow host alias to be specified in profile

  - Code readability enhancements

  - Solaris support has been improved

  - Fix for upload function to be used from profile

  - Reduce screen output for mail section, unless --verbose
    is used

  - Code cleanups and removed 'update release' command

  - Colored output can now be tuned with profile
    (colors=yes/no)

  - Allow data upload to be set as a profile option

  - Properly detect SSH daemon version

  - Generic code improvements

  - Improved the update check and display

  - Finish, Portuguese, and Turkish translation

  - Extended support and tests for DragonFlyBSD

  - Option to configure hostid and hostid2 in profile

  - Support for Trend Micro and Cylance (macOS)

  - Remove comments at end of nginx configuration

  - Used machine ID to create host ID when no SSH keys are
    available

  - Added detection of iptables-save to binaries

And Lynis 2.4.0 

  - Mainly improved support for macOS users

  - Support for CoreOS

  - Support for clamconf utility

  - Support for chinese translation

  - More sysctl values in the default profile

  - New commands: 'upload-only', 'show hostids', 'show
    environment', 'show os'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043463"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lynis package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lynis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"lynis-2.5.1-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lynis");
}
