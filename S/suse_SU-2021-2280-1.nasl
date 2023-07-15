#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:2280-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151491);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/09");

  script_cve_id("CVE-2019-3688", "CVE-2019-3690", "CVE-2020-8013");
  script_xref(name:"SuSE", value:"SUSE-SU-2021:2280-1");

  script_name(english:"SUSE SLES12 Security Update : permissions (SUSE-SU-2021:2280-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:2280-1 advisory.

  - The /usr/sbin/pinger binary packaged with squid in SUSE Linux Enterprise Server 15 before and including
    version 4.8-5.8.1 and in SUSE Linux Enterprise Server 12 before and including 3.5.21-26.17.1 had
    squid:root, 0750 permissions. This allowed an attacker that compromissed the squid user to gain
    persistence by changing the binary (CVE-2019-3688)

  - The chkstat tool in the permissions package followed symlinks before commit
    a9e1d26cd49ef9ee0c2060c859321128a6dd4230 (please also check the additional hardenings after this fix).
    This allowed local attackers with control over a path that is traversed by chkstat to escalate privileges.
    (CVE-2019-3690)

  - A UNIX Symbolic Link (Symlink) Following vulnerability in chkstat of SUSE Linux Enterprise Server 12, SUSE
    Linux Enterprise Server 15, SUSE Linux Enterprise Server 11 set permissions intended for specific binaries
    on other binaries because it erroneously followed symlinks. The symlinks can't be controlled by attackers
    on default systems, so exploitation is difficult. This issue affects: SUSE Linux Enterprise Server 12
    permissions versions prior to 2015.09.28.1626-17.27.1. SUSE Linux Enterprise Server 15 permissions
    versions prior to 20181116-9.23.1. SUSE Linux Enterprise Server 11 permissions versions prior to
    2013.1.7-0.6.12.1. (CVE-2020-8013)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1047247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1050467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1093414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1097665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1123886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1150734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1155939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1161779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1163922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182899");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-July/009118.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b2243e1");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8013");
  script_set_attribute(attribute:"solution", value:
"Update the affected permissions package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3690");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:permissions");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'permissions-20170707-6.4.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'permissions-20170707-6.4.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'permissions');
}
