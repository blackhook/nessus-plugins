#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6120-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176492);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/09");

  script_cve_id(
    "CVE-2023-25735",
    "CVE-2023-25739",
    "CVE-2023-25751",
    "CVE-2023-29535",
    "CVE-2023-29536",
    "CVE-2023-29548",
    "CVE-2023-29550",
    "CVE-2023-32211",
    "CVE-2023-32215"
  );
  script_xref(name:"USN", value:"6120-1");

  script_name(english:"Ubuntu 22.04 LTS : SpiderMonkey vulnerabilities (USN-6120-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-6120-1 advisory.

  - Cross-compartment wrappers wrapping a scripted proxy could have caused objects from other compartments to
    be stored in the main compartment resulting in a use-after-free after unwrapping the proxy.
    (CVE-2023-25735)

  - Module load requests that failed were not being checked as to whether or not they were cancelled causing a
    use-after-free in <code>ScriptLoadContext</code>.  (CVE-2023-25739)

  - Mozilla: Incorrect code generation during JIT compilation (CVE-2023-25751)

  - Following a Garbage Collector compaction, weak maps may have been accessed before they were correctly
    traced. This resulted in memory corruption and a potentially exploitable crash.  (CVE-2023-29535)

  - An attacker could cause the memory manager to incorrectly free a pointer that addresses attacker-
    controlled memory, resulting in an assertion, memory corruption, or a potentially exploitable crash.
    (CVE-2023-29536)

  - A wrong lowering instruction in the ARM64 Ion compiler resulted in a wrong optimization result.
    (CVE-2023-29548)

  - Mozilla developers Andrew Osmond, Sebastian Hengst, Andrew McCreight, and the Mozilla Fuzzing Team
    reported memory safety bugs present in Thunderbird 102.9. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some of these could have been exploited to run arbitrary
    code.  (CVE-2023-29550)

  - A type checking bug would have led to invalid code being compiled.  (CVE-2023-32211)

  - Mozilla developers and community members Gabriele Svelto, Andrew Osmond, Emily McDonough, Sebastian
    Hengst, Andrew McCreight and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 112
    and Firefox ESR 102.10. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code.  (CVE-2023-32215)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6120-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected libmozjs-102-0 and / or libmozjs-102-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32215");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmozjs-102-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmozjs-102-dev");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(22\.04|22\.10|23\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04 / 22.10 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.04', 'pkgname': 'libmozjs-102-0', 'pkgver': '102.11.0-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libmozjs-102-dev', 'pkgver': '102.11.0-0ubuntu0.22.04.1'},
    {'osver': '22.10', 'pkgname': 'libmozjs-102-0', 'pkgver': '102.11.0-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libmozjs-102-dev', 'pkgver': '102.11.0-0ubuntu0.22.10.1'},
    {'osver': '23.04', 'pkgname': 'libmozjs-102-0', 'pkgver': '102.11.0-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmozjs-102-dev', 'pkgver': '102.11.0-0ubuntu0.23.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmozjs-102-0 / libmozjs-102-dev');
}
