#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5252-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157112);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-4034");
  script_xref(name:"USN", value:"5252-1");
  script_xref(name:"IAVA", value:"2022-A-0055");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/18");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 : PolicyKit vulnerability (USN-5252-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 host has packages installed that are affected by a vulnerability as
referenced in the USN-5252-1 advisory.

  - A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is
    a setuid tool designed to allow unprivileged users to run commands as privileged users according
    predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly
    and ends trying to execute environment variables as commands. An attacker can leverage this by crafting
    environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully
    executed the attack can cause a local privilege escalation given unprivileged users administrative rights
    on the target machine. (CVE-2021-4034)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5252-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4034");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Local Privilege Escalation in polkits pkexec');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-polkit-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpolkit-agent-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpolkit-agent-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpolkit-backend-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpolkit-backend-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpolkit-gobject-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpolkit-gobject-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:policykit-1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|21\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'gir1.2-polkit-1.0', 'pkgver': '0.105-20ubuntu0.18.04.6'},
    {'osver': '18.04', 'pkgname': 'libpolkit-agent-1-0', 'pkgver': '0.105-20ubuntu0.18.04.6'},
    {'osver': '18.04', 'pkgname': 'libpolkit-agent-1-dev', 'pkgver': '0.105-20ubuntu0.18.04.6'},
    {'osver': '18.04', 'pkgname': 'libpolkit-backend-1-0', 'pkgver': '0.105-20ubuntu0.18.04.6'},
    {'osver': '18.04', 'pkgname': 'libpolkit-backend-1-dev', 'pkgver': '0.105-20ubuntu0.18.04.6'},
    {'osver': '18.04', 'pkgname': 'libpolkit-gobject-1-0', 'pkgver': '0.105-20ubuntu0.18.04.6'},
    {'osver': '18.04', 'pkgname': 'libpolkit-gobject-1-dev', 'pkgver': '0.105-20ubuntu0.18.04.6'},
    {'osver': '18.04', 'pkgname': 'policykit-1', 'pkgver': '0.105-20ubuntu0.18.04.6'},
    {'osver': '20.04', 'pkgname': 'gir1.2-polkit-1.0', 'pkgver': '0.105-26ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'libpolkit-agent-1-0', 'pkgver': '0.105-26ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'libpolkit-agent-1-dev', 'pkgver': '0.105-26ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'libpolkit-gobject-1-0', 'pkgver': '0.105-26ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'libpolkit-gobject-1-dev', 'pkgver': '0.105-26ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'policykit-1', 'pkgver': '0.105-26ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'gir1.2-polkit-1.0', 'pkgver': '0.105-31ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libpolkit-agent-1-0', 'pkgver': '0.105-31ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libpolkit-agent-1-dev', 'pkgver': '0.105-31ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libpolkit-gobject-1-0', 'pkgver': '0.105-31ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libpolkit-gobject-1-dev', 'pkgver': '0.105-31ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'policykit-1', 'pkgver': '0.105-31ubuntu0.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-polkit-1.0 / libpolkit-agent-1-0 / libpolkit-agent-1-dev / etc');
}
