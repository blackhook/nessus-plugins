#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-410.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(147780);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2020-35459", "CVE-2021-3020");

  script_name(english:"openSUSE Security Update : crmsh (openSUSE-2021-410)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for crmsh fixes the following issues :

  - Update to version 4.3.0+20210305.9db5c9a8 :

  - Fix: bootstrap: Adjust qdevice configure/remove process
    to avoid race condition due to quorum lost(bsc#1181415)

  - Dev: cibconfig: remove related code about detecting
    crm_diff support --no-verion

  - Fix: ui_configure: raise error when params not
    exist(bsc#1180126)

  - Dev: doc: remove doc for crm node status

  - Dev: ui_node: remove status subcommand

  - Update to version 4.3.0+20210219.5d1bf034 :

  - Fix: hb_report: walk through hb_report process under
    hacluster(CVE-2020-35459, bsc#1179999; CVE-2021-3020,
    bsc#1180571)

  - Fix: bootstrap: setup authorized ssh access for
    hacluster(CVE-2020-35459, bsc#1179999; CVE-2021-3020,
    bsc#1180571)

  - Dev: analyze: Add analyze sublevel and put
    preflight_check in it(jsc#ECO-1658)

  - Dev: utils: change default file mod as 644 for str2file
    function

  - Dev: hb_report: Detect if any ocfs2 partitions exist

  - Dev: lock: give more specific error message when raise
    ClaimLockError

  - Fix: Replace mktemp() to mkstemp() for security

  - Fix: Remove the duplicate --cov-report html in tox.

  - Fix: fix some lint issues.

  - Fix: Replace utils.msg_info to task.info

  - Fix: Solve a circular import error of utils.py

  - Fix: hb_report: run lsof with specific ocfs2
    device(bsc#1180688)

  - Dev: corosync: change the permission of corosync.conf to
    644

  - Fix: preflight_check: task: raise error when report_path
    isn't a directory

  - Fix: bootstrap: Use class Watchdog to simplify watchdog
    config(bsc#1154927, bsc#1178869)

  - Dev: Polish the sbd feature.

  - Dev: Replace -f with -c and run check when no parameter
    provide.

  - Fix: Fix the yes option not working

  - Fix: Remove useless import and show help when no input.

  - Dev: Correct SBD device id inconsistenc during ASR

  - Fix: completers: return complete start/stop resource id
    list correctly(bsc#1180137)

  - Dev: Makefile.am: change makefile to integrate
    preflight_check

  - Medium: integrate preflight_check into
    crmsh(jsc#ECO-1658)

  - Fix: bootstrap: make sure sbd device UUID was the same
    between nodes(bsc#1178454)

This update was imported from the SUSE:SLE-15-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180137");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181415");
  script_set_attribute(attribute:"solution", value:
"Update the affected crmsh packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35459");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3020");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crmsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crmsh-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crmsh-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.2", reference:"crmsh-4.3.0+20210305.9db5c9a8-lp152.4.47.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crmsh-scripts-4.3.0+20210305.9db5c9a8-lp152.4.47.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crmsh-test-4.3.0+20210305.9db5c9a8-lp152.4.47.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "crmsh / crmsh-scripts / crmsh-test");
}
