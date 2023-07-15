#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1520-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155823);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/03");

  script_cve_id("CVE-2019-3687", "CVE-2019-3688", "CVE-2020-8013");

  script_name(english:"openSUSE 15 Security Update : permissions (openSUSE-SU-2021:1520-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1520-1 advisory.

  - The permission package in SUSE Linux Enterprise Server allowed all local users to run dumpcap in the
    easy permission profile and sniff network traffic. This issue affects: SUSE Linux Enterprise Server
    permissions versions starting from 85c83fef7e017f8ab7f8602d3163786d57344439 to
    081d081dcfaf61710bda34bc21c80c66276119aa. (CVE-2019-3687)

  - The /usr/sbin/pinger binary packaged with squid in SUSE Linux Enterprise Server 15 before and including
    version 4.8-5.8.1 and in SUSE Linux Enterprise Server 12 before and including 3.5.21-26.17.1 had
    squid:root, 0750 permissions. This allowed an attacker that compromissed the squid user to gain
    persistence by changing the binary (CVE-2019-3688)

  - A UNIX Symbolic Link (Symlink) Following vulnerability in chkstat of SUSE Linux Enterprise Server 12, SUSE
    Linux Enterprise Server 15, SUSE Linux Enterprise Server 11 set permissions intended for specific binaries
    on other binaries because it erroneously followed symlinks. The symlinks can't be controlled by attackers
    on default systems, so exploitation is difficult. This issue affects: SUSE Linux Enterprise Server 12
    permissions versions prior to 2015.09.28.1626-17.27.1. SUSE Linux Enterprise Server 15 permissions
    versions prior to 20181116-9.23.1. SUSE Linux Enterprise Server 11 permissions versions prior to
    2013.1.7-0.6.12.1. (CVE-2020-8013)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1028975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1029961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1093414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1133678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1148788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1150345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1150366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1151190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1161335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1161779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1163588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1169614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171173");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173221");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183669");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CDE67H3SKCA2N6SED6KU5T3MBX3UVI6N/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3818419a");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8013");
  script_set_attribute(attribute:"solution", value:
"Update the affected permissions and / or permissions-zypp-plugin packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3688");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:permissions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:permissions-zypp-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
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
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'permissions-20200127-lp153.24.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'permissions-zypp-plugin-20200127-lp153.24.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'permissions / permissions-zypp-plugin');
}
