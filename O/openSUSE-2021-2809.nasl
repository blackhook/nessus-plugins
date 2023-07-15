#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:2809-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152768);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2020-13529", "CVE-2021-33910");
  script_xref(name:"IAVA", value:"2021-A-0350");

  script_name(english:"openSUSE 15 Security Update : systemd (openSUSE-SU-2021:2809-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:2809-1 advisory.

  - An exploitable denial-of-service vulnerability exists in Systemd 245. A specially crafted DHCP FORCERENEW
    packet can cause a server running the DHCP client to be vulnerable to a DHCP ACK spoofing attack. An
    attacker can forge a pair of FORCERENEW and DCHP ACK packets to reconfigure the server. (CVE-2020-13529)

  - basic/unit-name.c in systemd prior to 246.15, 247.8, 248.5, and 249.1 has a Memory Allocation with an
    Excessive Size Value (involving strdupa and alloca for a pathname controlled by a local attacker) that
    results in an operating system crash. (CVE-2021-33910)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1166028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188063");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PFXYBJHAFZNV57EZ4VL2LC446RMO7HVT/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d00f137");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13529");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33910");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33910");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-13529");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-resolve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-coredump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-journal-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
    {'reference':'libsystemd0-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsystemd0-32bit-246.15-7.11.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libudev-devel-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libudev-devel-32bit-246.15-7.11.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libudev1-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libudev1-32bit-246.15-7.11.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-myhostname-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-myhostname-32bit-246.15-7.11.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-mymachines-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-mymachines-32bit-246.15-7.11.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-resolve-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-systemd-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-32bit-246.15-7.11.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-coredump-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-lang-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-logger-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-network-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-sysvinit-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'udev-246.15-7.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsystemd0 / libsystemd0-32bit / libudev-devel / libudev-devel-32bit / etc');
}
