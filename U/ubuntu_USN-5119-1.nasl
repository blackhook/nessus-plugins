#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5119-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154328);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-30498", "CVE-2021-30499");
  script_xref(name:"USN", value:"5119-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 21.04 : libcaca vulnerabilities (USN-5119-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 21.04 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5119-1 advisory.

  - A flaw was found in libcaca. A heap buffer overflow in export.c in function export_tga might lead to
    memory corruption and other potential consequences. (CVE-2021-30498)

  - A flaw was found in libcaca. A buffer overflow of export.c in function export_troff might lead to memory
    corruption and other potential consequences. (CVE-2021-30499)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5119-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected caca-utils, libcaca-dev and / or libcaca0 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30499");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:caca-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcaca-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcaca0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '16.04', 'pkgname': 'caca-utils', 'pkgver': '0.99.beta19-2ubuntu0.16.04.2+esm1'},
    {'osver': '16.04', 'pkgname': 'libcaca-dev', 'pkgver': '0.99.beta19-2ubuntu0.16.04.2+esm1'},
    {'osver': '16.04', 'pkgname': 'libcaca0', 'pkgver': '0.99.beta19-2ubuntu0.16.04.2+esm1'},
    {'osver': '18.04', 'pkgname': 'caca-utils', 'pkgver': '0.99.beta19-2ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libcaca-dev', 'pkgver': '0.99.beta19-2ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libcaca0', 'pkgver': '0.99.beta19-2ubuntu0.18.04.3'},
    {'osver': '20.04', 'pkgname': 'caca-utils', 'pkgver': '0.99.beta19-2.1ubuntu1.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libcaca-dev', 'pkgver': '0.99.beta19-2.1ubuntu1.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libcaca0', 'pkgver': '0.99.beta19-2.1ubuntu1.20.04.2'},
    {'osver': '21.04', 'pkgname': 'caca-utils', 'pkgver': '0.99.beta19-2.2ubuntu1.1'},
    {'osver': '21.04', 'pkgname': 'libcaca-dev', 'pkgver': '0.99.beta19-2.2ubuntu1.1'},
    {'osver': '21.04', 'pkgname': 'libcaca0', 'pkgver': '0.99.beta19-2.2ubuntu1.1'}
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'caca-utils / libcaca-dev / libcaca0');
}
