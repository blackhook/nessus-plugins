#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1173.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104078);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15194");

  script_name(english:"openSUSE Security Update : cacti and cacti-spine (openSUSE-2017-1173)");
  script_summary(english:"Check for the openSUSE-2017-1173 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for cacti and cacti-spine fixes the following issues :

Build version 1.1.26

  - issue#841: --input-fields variable not working with
    add_graphs.php cli

  - issue#986: Resolve minor appearance problem on Modern
    theme

  - issue#989: Resolve issue with data input method commands
    loosing spaces on import

  - issue#1000: add_graphs.php not recognizing input fields

  - issue#1003: Reversing resolution to Issue#995 due to
    adverse impact to polling times

  - issue#1008: Remove developer debug warning about
    thumbnail validation

  - issue#1009: Resolving minor issue with cmd_realtime.php
    and a changing hostname

  - issue#1010: CVE-2017-15194 - Path-Based Cross-Site
    Scripting (XSS) (bsc#1062554)

  - issue#1027: Confirm that the PHP date.timezone setting
    is properly set during install

  - issue: Fixed database session handling for PHP 7.1

  - issue: Fixed some missing i18n

  - issue: Fixed typo's

  - feature: Updated Dutch translations

  - feature: Schema changes; Examined queries without key
    usage and added/changed some keys

  - feature: Some small improvements Build version 1.1.25

  - issue#966: Email still using SMTP security even though
    set to none

  - issue#995: Redirecting exec_background() to dev null
    breaks some functions

  - issue#998: Allow removal of external data template and
    prevent their creation

  - issue: Remove spikes uses wrong variance value from
    WebGUI

  - issue: Changing filters on log page does not reset to
    first page

  - issue: Allow manual creation of external data sources
    once again

  - feature: Updated Dutch translations

Build version 1.1.24

  - issue#932: Zoom positioning breaks when you scroll the
    graph page

  - issue#970: Remote Data Collector Cache Synchronization
    missing plugin sub-directories

  - issue#980: Resolve issue where a new tree branches
    refreshs before you have a chance to name it

  - issue#982: Data Source Profile size information not
    showing properly

  - issue: Long sysDescriptions on automation page cause
    columns to be hidden

  - issue: Resolve visual issues in Classic theme

  - feature: Allow Resynchronization of Poller Resource
    Cache

Build version 1.1.23

  - issue#963: SQL Errors with snmpagent and MariaDB 10.2

  - issue#964: SQL Mode optimization failing in 1.1.22

Build version 1.1.22

  - issue#950: Automation - New graph rule looses name on
    change

  - issue#952: CSV Export not rendering chinese characters
    correctly (Second attempt)

  - issue#955: Validation error trying to view graph debug
    syntax

  - issue: MySQL/MariaDB database sql_mode
    NO_AUTO_VALUE_ON_ZERO corrupts Cacti database

  - issue: When creating a data source, the data source
    profile does not default to the system default

  - feature: Enhance table filters to support new Cycle
    plugin

  - feature: Updated Dutch Translations

Build version 1.1.21

  - issue#938: Problems upgrading to 1.1.20 with one table
    alter statement

  - issue#952: CSV Export not rendering chinese characters
    correctly

  - issue: Minor alignment issue on tables

Build version 1.1.20

  - issue#920: Issue with scrollbars after update to 1.1.19
    related to #902

  - issue#921: Tree Mode no longer expands to accomodate
    full tree item names

  - issue#922: When using LDAP domains some setings are not
    passed correctly to the Cacti LDAP library

  - issue#923: Warninga in cacti.log are displayed
    incorrectly

  - issue#926: Update Utilities page to provide more
    information on rebuilding poller cache

  - issue#927: Minor schema change to support XtraDB Cluster

  - issue#929: Overlapping frames on certain themes

  - issue#931: Aggregate graphs missing from list view

  - issue#933: Aggregate graphs page counter off

  - issue#935: Support utf8 printable in data query inserts

  - issue#936: TimeZone query failure undefined function

  - issue: Taking actions on users does not use callbacks

  - issue: Undefined constant in lib/snmp.php on RHEL7

  - issue: Human readable socket errno's not defined

  - issue: Audit of ping methods tcp, udp, and icmp ping.
    IPv6 will still not work till php 5.5.4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062554"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cacti and cacti-spine packages."
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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/23");
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

if ( rpm_check(release:"SUSE42.2", reference:"cacti-1.1.26-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"cacti-spine-1.1.26-7.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"cacti-spine-debuginfo-1.1.26-7.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"cacti-spine-debugsource-1.1.26-7.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cacti-1.1.26-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cacti-spine-1.1.26-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cacti-spine-debuginfo-1.1.26-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cacti-spine-debugsource-1.1.26-16.1") ) flag++;

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
