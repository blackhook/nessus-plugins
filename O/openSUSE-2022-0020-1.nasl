#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0020-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157096);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/25");

  script_cve_id("CVE-2022-21394");
  script_xref(name:"IAVA", value:"2022-A-0034-S");

  script_name(english:"openSUSE 15 Security Update : virtualbox (openSUSE-SU-2022:0020-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by a vulnerability as referenced in the
openSUSE-SU-2022:0020-1 advisory.

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.32. Easily exploitable vulnerability allows low
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in unauthorized access to
    critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 6.5
    (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N). (CVE-2022-21394)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194924");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OVT7FRNNNK2PC4PFXSGAPUIG3HECY4P5/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40ef5e58");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21394");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21394");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/26");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'python3-virtualbox-6.1.32-lp153.2.21.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-6.1.32-lp153.2.21.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-devel-6.1.32-lp153.2.21.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-guest-desktop-icons-6.1.32-lp153.2.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-guest-source-6.1.32-lp153.2.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-guest-tools-6.1.32-lp153.2.21.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-guest-x11-6.1.32-lp153.2.21.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-host-source-6.1.32-lp153.2.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-kmp-default-6.1.32_k5.3.18_59.40-lp153.2.21.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-kmp-preempt-6.1.32_k5.3.18_59.40-lp153.2.21.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-qt-6.1.32-lp153.2.21.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-vnc-6.1.32-lp153.2.21.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-websrv-6.1.32-lp153.2.21.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
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
