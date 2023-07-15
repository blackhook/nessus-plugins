#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0166-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(177993);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/05");

  script_cve_id(
    "CVE-2023-21987",
    "CVE-2023-21988",
    "CVE-2023-21989",
    "CVE-2023-21990",
    "CVE-2023-21991",
    "CVE-2023-21998",
    "CVE-2023-21999",
    "CVE-2023-22000",
    "CVE-2023-22001",
    "CVE-2023-22002"
  );
  script_xref(name:"IAVA", value:"2023-A-0216");

  script_name(english:"openSUSE 15 Security Update : virtualbox (openSUSE-SU-2023:0166-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2023:0166-1 advisory.

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
    versions that are affected are Prior to 6.1.44 and Prior to 7.0.8. Difficult to exploit vulnerability
    allows low privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may
    significantly impact additional products (scope change). Successful attacks of this vulnerability can
    result in takeover of Oracle VM VirtualBox. (CVE-2023-21987)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
    versions that are affected are Prior to 6.1.44 and Prior to 7.0.8. Easily exploitable vulnerability allows
    low privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products (scope change). Successful attacks of this vulnerability can result in unauthorized
    read access to a subset of Oracle VM VirtualBox accessible data. (CVE-2023-21988)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
    versions that are affected are Prior to 6.1.44 and Prior to 7.0.8. Easily exploitable vulnerability allows
    high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may
    significantly impact additional products (scope change). Successful attacks of this vulnerability can
    result in unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible
    data. (CVE-2023-21989, CVE-2023-22002)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
    versions that are affected are Prior to 6.1.44 and Prior to 7.0.8. Easily exploitable vulnerability allows
    high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may
    significantly impact additional products (scope change). Successful attacks of this vulnerability can
    result in takeover of Oracle VM VirtualBox. (CVE-2023-21990)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
    versions that are affected are Prior to 6.1.44 and Prior to 7.0.8. Easily exploitable vulnerability allows
    high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may
    significantly impact additional products (scope change). Successful attacks of this vulnerability can
    result in unauthorized read access to a subset of Oracle VM VirtualBox accessible data. (CVE-2023-21991)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
    versions that are affected are Prior to 6.1.44 and Prior to 7.0.8. Easily exploitable vulnerability allows
    high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may
    significantly impact additional products (scope change). Successful attacks of this vulnerability can
    result in unauthorized update, insert or delete access to some of Oracle VM VirtualBox accessible data as
    well as unauthorized read access to a subset of Oracle VM VirtualBox accessible data. Note: This
    vulnerability applies to Windows VMs only. (CVE-2023-21998)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
    versions that are affected are Prior to 6.1.44 and Prior to 7.0.8. Difficult to exploit vulnerability
    allows low privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Oracle VM VirtualBox accessible data as well as unauthorized
    read access to a subset of Oracle VM VirtualBox accessible data. (CVE-2023-21999)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
    versions that are affected are Prior to 6.1.44 and Prior to 7.0.8. Easily exploitable vulnerability allows
    high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may
    significantly impact additional products (scope change). Successful attacks of this vulnerability can
    result in unauthorized update, insert or delete access to some of Oracle VM VirtualBox accessible data as
    well as unauthorized read access to a subset of Oracle VM VirtualBox accessible data. (CVE-2023-22000,
    CVE-2023-22001)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211941");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AK32QNGMLSYI23PSUJJUNPLZUBS2G3HB/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32aa222a");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21987");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22002");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21990");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.4)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.4', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'python3-virtualbox-7.0.8-lp154.2.32.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-7.0.8-lp154.2.32.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-devel-7.0.8-lp154.2.32.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-guest-desktop-icons-7.0.8-lp154.2.32.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-guest-source-7.0.8-lp154.2.32.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-guest-tools-7.0.8-lp154.2.32.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-host-source-7.0.8-lp154.2.32.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-kmp-default-7.0.8_k5.14.21_150400.24.63-lp154.2.32.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-qt-7.0.8-lp154.2.32.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-vnc-7.0.8-lp154.2.32.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-websrv-7.0.8-lp154.2.32.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-virtualbox / virtualbox / virtualbox-devel / etc');
}
