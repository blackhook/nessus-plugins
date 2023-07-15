#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-706.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149537);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/18");

  script_name(english:"openSUSE Security Update : monitoring-plugins-smart (openSUSE-2021-706)");
  script_summary(english:"Check for the openSUSE-2021-706 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for monitoring-plugins-smart fixes the following issues :

monitoring-plugins-smart was updated to 6.9.1 :

This is a security-release (boo#1183057)

  + Fixes the regular expression for pseudo-devices under
    the /dev/bus/N path. from 6.9.0

  + Allows using PCI device paths as device name(s) (#64)

  + Introduce new optional parameter -l/--ssd-lifetime)
    which additionally checks SMART attribute
    'Percent_Lifetime_Remain' (available on some SSD
    drives). (#66 #67) from 6.8.0

  + Allow skip self-assessment check
    (--skip-self-assessment)

  + Add Command_Timeout to default raw list from 6.7.1

  + Bugfix to make --warn work (issue #54) from 6.7.0

  + Added support for NVMe drives from 6.6.1

  + Fix 'deprecation warning on regex with curly brackets'
    (6.6.1) from 6.6.0

  + The feature was requested in #30 . This PR adds the
    possibility to use 3ware,N and cciss,N drives in
    combination with the global -g parameter.

  + Furthermore this PR adjusts the output of the plugin
    when the -g is used in combination with hardware raid
    controllers. Instead of showing the logical device name
    (/dev/sda for example), the plugin will now show the
    controller with drive number from 6.5.0 :

  + Add Reported_Uncorrect and Reallocated_Event_Count to
    default raw list.

  + As of 6.5 the following SMART attributes are by default
    checked and may result in alert when threshold (default
    0 is reached):
    'Current_Pending_Sector,Reallocated_Sector_Ct,Program_Fa
    il_Cnt_Total,
    Uncorrectable_Error_Cnt,Offline_Uncorrectable,Runtime_Ba
    d_Block, Reported_Uncorrect,Reallocated_Event_Count'

  - Update to version 6.4

  - Allow detection of more than 26 devices / issue #5 (rev
    5.3)

  - Different ATA vs. SCSI lookup (rev 5.4)

  - Allow script to run outside of nagios plugins dir / wiki
    url update (rev 5.5)

  - Change syntax of -g parameter (regex is now awaited from
    input) (rev 5.6)

  - Fix Use of uninitialized value $device (rev 5.7)

  - Allow multiple devices for interface type megaraid, e.g.
    'megaraid,[1-5]' (rev 5.8)

  - allow type 'auto' (rev 5.9)

  - Check selftest log for errors using new parameter -s
    (rev 5.10)

  - Add exclude list (-e) to ignore certain attributes
    (5.11)

  - Fix 'Use of uninitialized value' warnings (5.11.1)

  - Add raw check list (-r) and warning thresholds (-w)
    (6.0)

  - Allow using pseudo bus device /dev/bus/N (6.1)

  - Add device model and serial number in output (6.2)

  - Allow exclusion from perfdata as well (-E) and by
    attribute number (6.3)

  - Remove dependency on utils.pm, add quiet parameter (6.4)

  - Drop not longer needed patch :

  - enable_auto_interface.patch (obsolete, type auto was
    added upstream in v5.9)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183057"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected monitoring-plugins-smart package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:monitoring-plugins-smart");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"monitoring-plugins-smart-6.9.1-lp152.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "monitoring-plugins-smart");
}
