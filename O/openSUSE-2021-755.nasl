#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-755.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149884);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/27");

  script_cve_id("CVE-2020-35701");

  script_name(english:"openSUSE Security Update : cacti / cacti-spine (openSUSE-2021-755)");
  script_summary(english:"Check for the openSUSE-2021-755 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for cacti, cacti-spine fixes the following issues :

cacti-spine was updated to 1.2.17 :

  - Avoid triggering DDos detection in firewalls on large
    systems

  - Use mysql reconnect option properly

  - Fix possible creashes in various operations

  - Fix remote data collectors pushing too much data to main
    when performing diagnostics

  - Make spine more responsive when remote connection is
    down

  - Fix various MySQL issues

  - Make spine immune to DST changes

cacti-spine 1.2.16 :

  - Some developer debug log messages falsely labeled as
    WARNINGS

  - Remove the need of the dos2unix program

  - Fix Spine experiencing MySQL socket error 2002 under
    load

  - Under heavy load MySQL/MariaDB return 2006 and 2013
    errors on query

  - Add backtrace output to stderr for signals

  - Add Data Source turnaround time to debug output

cacti-spine 1.2.15 :

  - Special characters may not always be ignored properly

cacti was updated to 1.2.17 :

  - Fix incorrect handling of fields led to potential XSS
    issues

  - CVE-2020-35701: Fix SQL Injection vulnerability
    (boo#1180804)

  - Fix various XSS issues with HTML Forms handling

  - Fix handling of Daylight Saving Time changes

  - Multiple fixes and extensions to plugins

  - Fix multiple display, export, and input validation
    issues

  - SNMPv3 Password field was not correctly limited

  - Improved regular expression handling for searcu

  - Improved support for RRDproxy

  - Improved behavior on large systems

  - MariaDB/MysQL: Support persistent connections and
    improve multiple operations and options

  - Add Theme 'Midwinter'

  - Modify automation to test for data before creating
    graphs

  - Add hooks for plugins to show customize graph source and
    customize template url

  - Allow CSRF security key to be refreshed at command line

  - Allow remote pollers statistics to be cleared

  - Allow user to be automatically logged out after admin
    defined period

  - When replicating, ensure Cacti can detect and verify
    replica servers"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180804"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected cacti / cacti-spine packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"cacti-1.2.17-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cacti-spine-1.2.17-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cacti-spine-debuginfo-1.2.17-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cacti-spine-debugsource-1.2.17-lp152.2.9.1") ) flag++;

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
