##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:0723-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(149539);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2021-2145",
    "CVE-2021-2250",
    "CVE-2021-2264",
    "CVE-2021-2266",
    "CVE-2021-2279",
    "CVE-2021-2280",
    "CVE-2021-2281",
    "CVE-2021-2282",
    "CVE-2021-2283",
    "CVE-2021-2284",
    "CVE-2021-2285",
    "CVE-2021-2286",
    "CVE-2021-2287",
    "CVE-2021-2291",
    "CVE-2021-2296",
    "CVE-2021-2297",
    "CVE-2021-2306",
    "CVE-2021-2309",
    "CVE-2021-2310",
    "CVE-2021-2312",
    "CVE-2021-25319"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"openSUSE 15 Security Update : virtualbox (openSUSE-SU-2021:0723-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for virtualbox fixes the following issues :

  - A Incorrect Default Permissions vulnerability in the packaging of virtualbox of openSUSE Factory allows
    local attackers in the vboxusers groupu to escalate to root. This issue affects: openSUSE Factory
    virtualbox version 6.1.20-1.1 and prior versions. (CVE-2021-25319)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.20. Difficult to exploit vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in takeover of Oracle VM
    VirtualBox. (CVE-2021-2145, CVE-2021-2309, CVE-2021-2310)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.20. Easily exploitable vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in takeover of Oracle VM
    VirtualBox. (CVE-2021-2250)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.20. Easily exploitable vulnerability allows low
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in unauthorized creation,
    deletion or modification access to critical data or all Oracle VM VirtualBox accessible data as well as
    unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data.
    (CVE-2021-2264)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.20. Easily exploitable vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in unauthorized access to
    critical data or complete access to all Oracle VM VirtualBox accessible data. (CVE-2021-2266,
    CVE-2021-2306)

  - Improve autostart security boo#1182918.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182918");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/H2VYFQN75RCOBQFQCIU4LU7E32CGO4SK/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?441fb2bc");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2250");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2264");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2266");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2279");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2282");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2283");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2284");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2286");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2287");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2291");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2296");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2297");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2306");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2309");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2310");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2312");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25319");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25319");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-2264");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'python3-virtualbox-6.1.22-lp152.2.24.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-6.1.22-lp152.2.24.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-devel-6.1.22-lp152.2.24.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-guest-desktop-icons-6.1.22-lp152.2.24.2', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-guest-source-6.1.22-lp152.2.24.2', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-guest-tools-6.1.22-lp152.2.24.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-guest-x11-6.1.22-lp152.2.24.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-host-source-6.1.22-lp152.2.24.2', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-kmp-default-6.1.22_k5.3.18_lp152.75-lp152.2.24.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-kmp-preempt-6.1.22_k5.3.18_lp152.75-lp152.2.24.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-qt-6.1.22-lp152.2.24.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-vnc-6.1.22-lp152.2.24.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-websrv-6.1.22-lp152.2.24.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
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
