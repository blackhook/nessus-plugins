#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-261.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(134193);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/06");

  script_cve_id("CVE-2019-0804");

  script_name(english:"openSUSE Security Update : python-azure-agent (openSUSE-2020-261)");
  script_summary(english:"Check for the openSUSE-2020-261 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for python-azure-agent fixes the following issues :

python-azure-agent was updated to version 2.2.45 (jsc#ECO-80)

  + Add support for Gen2 VM resource disks

  + Use alternate systemd detection

  + Fix /proc/net/route requirement that causes errors on
    FreeBSD

  + Add cloud-init auto-detect to prevent multiple
    provisioning mechanisms from relying on configuration
    for coordination

  + Disable cgroups when daemon is setup incorrectly

  + Remove upgrade extension loop for the same goal state

  + Add container id for extension telemetry events

  + Be more exact when detecting IMDS service health

  + Changing add_event to start sending missing fields

From 2.2.44 update :

  + Remove outdated extension ZIP packages

  + Improved error handling when starting extensions using
    systemd

  + Reduce provisioning time of some custom images

  + Improve the handling of extension download errors

  + New API for extension authors to handle errors during
    extension update

  + Fix handling of errors in calls to openssl

  + Improve logic to determine current distro

  + Reduce verbosity of several logging statements

From 2.2.42 update :

  + Poll for artifact blob, addresses goal state procesing
    issue

From 2.2.41 update :

  + Rewriting the mechanism to start the extension using
    systemd-run for systems using systemd for managing

  + Refactoring of resource monitoring framework using
    cgroup for both systemd and non-systemd approaches
    [#1530, #1534]

  + Telemetry pipeline for resource monitoring data

From 2.2.40 update :

  + Fixed tracking of memory/cpu usage

  + Do not prevent extensions from running if setting up
    cgroups fails

  + Enable systemd-aware deprovisioning on all versions >=
    18.04

  + Add systemd support for Debian Jessie, Stretch, and
    Buster

  + Support for Linux Openwrt

From 2.2.38 update :

Security issue fixed :

  + CVE-2019-0804: An issue with swapfile handling in the
    agent creates a data leak situation that exposes system
    memory data. (bsc#1127838)

  + Add fixes for handling swap file and other nit fixes

From 2.2.37 update :

  + Improves re-try logic to handle errors while downloading
    extensions

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127838"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-azure-agent packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-azure-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-azure-agent-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"python-azure-agent-2.2.45-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-azure-agent-test-2.2.45-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-azure-agent / python-azure-agent-test");
}
