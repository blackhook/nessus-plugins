#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:14753-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151084);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/01");

  script_cve_id("CVE-2021-31607");
  script_xref(name:"SuSE", value:"SUSE-SU-2021:14753-1");
  script_xref(name:"IAVA", value:"2021-A-0524-S");

  script_name(english:"SUSE SLES11 Security Update : SUSE Manager Client Tools (SUSE-SU-2021:14753-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by a vulnerability as referenced in the SUSE-
SU-2021:14753-1 advisory.

  - In SaltStack Salt 2016.9 through 3002.6, a command injection vulnerability exists in the snapper module
    that allows for local privilege escalation on a minion. The attack requires that a file is created with a
    pathname that is backed up by snapper, and that the master calls the snapper.diff function (which executes
    popen unsafely). (CVE-2021-31607)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185281");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-June/009060.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c0a65cb");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-31607");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31607");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:golang-github-wrouesnel-postgres_exporter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-cfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-cfg-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-cfg-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-cfg-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-custom-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-osad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-push");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-virtualization-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-cfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-cfg-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-cfg-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-cfg-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-osa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-osad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-push");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-virtualization-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-mgr-virtualization-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-rhnlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-spacewalk-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-spacewalk-client-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-spacewalk-client-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-spacewalk-koan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-spacewalk-oscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-suseRegisterInfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-uyuni-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacecmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-client-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-client-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-koan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-oscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-remote-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:supportutils-plugin-susemanager-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:suseRegisterInfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'golang-github-wrouesnel-postgres_exporter-0.4.7-5.12.1', 'sp':'3', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'golang-github-wrouesnel-postgres_exporter-0.4.7-5.12.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-cfg-4.2.2-5.15.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-cfg-actions-4.2.2-5.15.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-cfg-client-4.2.2-5.15.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-cfg-management-4.2.2-5.15.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-custom-info-4.2.1-5.9.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-daemon-4.2.7-5.26.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-osad-4.2.5-5.27.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-push-4.2.2-5.9.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-virtualization-host-4.2.1-5.17.3', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-cfg-4.2.2-5.15.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-cfg-actions-4.2.2-5.15.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-cfg-client-4.2.2-5.15.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-cfg-management-4.2.2-5.15.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-osa-common-4.2.5-5.27.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-osad-4.2.5-5.27.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-push-4.2.2-5.9.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-virtualization-common-4.2.1-5.17.3', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-mgr-virtualization-host-4.2.1-5.17.3', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-rhnlib-4.2.3-12.31.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-spacewalk-check-4.2.10-27.50.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-spacewalk-client-setup-4.2.10-27.50.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-spacewalk-client-tools-4.2.10-27.50.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-spacewalk-koan-4.2.3-9.21.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-spacewalk-oscap-4.2.1-6.15.3', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-suseRegisterInfo-4.2.3-6.15.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-uyuni-common-libs-4.2.3-5.12.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'salt-2016.11.10-43.75.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'salt-doc-2016.11.10-43.75.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'salt-minion-2016.11.10-43.75.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'spacecmd-4.2.8-18.84.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'spacewalk-check-4.2.10-27.50.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'spacewalk-client-setup-4.2.10-27.50.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'spacewalk-client-tools-4.2.10-27.50.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'spacewalk-koan-4.2.3-9.21.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'spacewalk-oscap-4.2.1-6.15.3', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'spacewalk-remote-utils-4.2.1-6.18.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'supportutils-plugin-susemanager-client-4.2.2-9.21.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'suseRegisterInfo-4.2.3-6.15.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'golang-github-wrouesnel-postgres_exporter-0.4.7-5.12.1', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'golang-github-wrouesnel-postgres_exporter-0.4.7-5.12.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-cfg-4.2.2-5.15.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-cfg-actions-4.2.2-5.15.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-cfg-client-4.2.2-5.15.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-cfg-management-4.2.2-5.15.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-custom-info-4.2.1-5.9.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-daemon-4.2.7-5.26.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-osad-4.2.5-5.27.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-push-4.2.2-5.9.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-virtualization-host-4.2.1-5.17.3', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-cfg-4.2.2-5.15.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-cfg-actions-4.2.2-5.15.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-cfg-client-4.2.2-5.15.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-cfg-management-4.2.2-5.15.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-osa-common-4.2.5-5.27.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-osad-4.2.5-5.27.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-push-4.2.2-5.9.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-virtualization-common-4.2.1-5.17.3', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-mgr-virtualization-host-4.2.1-5.17.3', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-rhnlib-4.2.3-12.31.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-spacewalk-check-4.2.10-27.50.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-spacewalk-client-setup-4.2.10-27.50.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-spacewalk-client-tools-4.2.10-27.50.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-spacewalk-koan-4.2.3-9.21.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-spacewalk-oscap-4.2.1-6.15.3', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-suseRegisterInfo-4.2.3-6.15.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-uyuni-common-libs-4.2.3-5.12.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'salt-2016.11.10-43.75.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'salt-doc-2016.11.10-43.75.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'salt-minion-2016.11.10-43.75.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'spacecmd-4.2.8-18.84.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'spacewalk-check-4.2.10-27.50.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'spacewalk-client-setup-4.2.10-27.50.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'spacewalk-client-tools-4.2.10-27.50.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'spacewalk-koan-4.2.3-9.21.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'spacewalk-oscap-4.2.1-6.15.3', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'spacewalk-remote-utils-4.2.1-6.18.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'supportutils-plugin-susemanager-client-4.2.2-9.21.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'suseRegisterInfo-4.2.3-6.15.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'golang-github-wrouesnel-postgres_exporter-0.4.7-5.12.1', 'sp':'3', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'golang-github-wrouesnel-postgres_exporter-0.4.7-5.12.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-cfg-4.2.2-5.15.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-cfg-actions-4.2.2-5.15.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-cfg-client-4.2.2-5.15.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-cfg-management-4.2.2-5.15.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-custom-info-4.2.1-5.9.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-daemon-4.2.7-5.26.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-osad-4.2.5-5.27.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-push-4.2.2-5.9.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-virtualization-host-4.2.1-5.17.3', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-cfg-4.2.2-5.15.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-cfg-actions-4.2.2-5.15.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-cfg-client-4.2.2-5.15.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-cfg-management-4.2.2-5.15.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-osa-common-4.2.5-5.27.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-osad-4.2.5-5.27.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-push-4.2.2-5.9.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-virtualization-common-4.2.1-5.17.3', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-mgr-virtualization-host-4.2.1-5.17.3', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-rhnlib-4.2.3-12.31.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-spacewalk-check-4.2.10-27.50.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-spacewalk-client-setup-4.2.10-27.50.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-spacewalk-client-tools-4.2.10-27.50.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-spacewalk-koan-4.2.3-9.21.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-spacewalk-oscap-4.2.1-6.15.3', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-suseRegisterInfo-4.2.3-6.15.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-uyuni-common-libs-4.2.3-5.12.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'salt-2016.11.10-43.75.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'salt-doc-2016.11.10-43.75.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'salt-minion-2016.11.10-43.75.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'spacecmd-4.2.8-18.84.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'spacewalk-check-4.2.10-27.50.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'spacewalk-client-setup-4.2.10-27.50.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'spacewalk-client-tools-4.2.10-27.50.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'spacewalk-koan-4.2.3-9.21.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'spacewalk-oscap-4.2.1-6.15.3', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'spacewalk-remote-utils-4.2.1-6.18.2', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'supportutils-plugin-susemanager-client-4.2.2-9.21.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'suseRegisterInfo-4.2.3-6.15.1', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'golang-github-wrouesnel-postgres_exporter-0.4.7-5.12.1', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'golang-github-wrouesnel-postgres_exporter-0.4.7-5.12.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mgr-cfg-4.2.2-5.15.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mgr-cfg-actions-4.2.2-5.15.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mgr-cfg-client-4.2.2-5.15.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mgr-cfg-management-4.2.2-5.15.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mgr-custom-info-4.2.1-5.9.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mgr-daemon-4.2.7-5.26.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mgr-osad-4.2.5-5.27.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mgr-push-4.2.2-5.9.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mgr-virtualization-host-4.2.1-5.17.3', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-cfg-4.2.2-5.15.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-cfg-actions-4.2.2-5.15.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-cfg-client-4.2.2-5.15.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-cfg-management-4.2.2-5.15.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-osa-common-4.2.5-5.27.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-osad-4.2.5-5.27.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-push-4.2.2-5.9.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-virtualization-common-4.2.1-5.17.3', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-mgr-virtualization-host-4.2.1-5.17.3', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-rhnlib-4.2.3-12.31.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-spacewalk-check-4.2.10-27.50.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-spacewalk-client-setup-4.2.10-27.50.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-spacewalk-client-tools-4.2.10-27.50.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-spacewalk-koan-4.2.3-9.21.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-spacewalk-oscap-4.2.1-6.15.3', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-suseRegisterInfo-4.2.3-6.15.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-uyuni-common-libs-4.2.3-5.12.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'salt-2016.11.10-43.75.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'salt-doc-2016.11.10-43.75.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'salt-minion-2016.11.10-43.75.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'spacecmd-4.2.8-18.84.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'spacewalk-check-4.2.10-27.50.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'spacewalk-client-setup-4.2.10-27.50.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'spacewalk-client-tools-4.2.10-27.50.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'spacewalk-koan-4.2.3-9.21.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'spacewalk-oscap-4.2.1-6.15.3', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'spacewalk-remote-utils-4.2.1-6.18.2', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'supportutils-plugin-susemanager-client-4.2.2-9.21.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'suseRegisterInfo-4.2.3-6.15.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-github-wrouesnel-postgres_exporter / mgr-cfg / mgr-cfg-actions / etc');
}
