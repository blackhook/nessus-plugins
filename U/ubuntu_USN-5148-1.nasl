##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5148-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(155375);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-3504");
  script_xref(name:"USN", value:"5148-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.04 / 21.10 : hivex vulnerability (USN-5148-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.04 host has packages installed that are affected by a vulnerability as
referenced in the USN-5148-1 advisory.

  - A flaw was found in the hivex library in versions before 1.3.20. It is caused due to a lack of bounds
    check within the hivex_open function. An attacker could input a specially crafted Windows Registry (hive)
    file which would cause hivex to read memory beyond its normal bounds or cause the program to crash. The
    highest threat from this vulnerability is to system availability. (CVE-2021-3504)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5148-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3504");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libhivex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libhivex-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libhivex-ocaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libhivex-ocaml-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libhivex0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwin-hivex-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby-hivex");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(18\.04|20\.04|21\.04|21\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.04 / 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libhivex-bin', 'pkgver': '1.3.15-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libhivex-dev', 'pkgver': '1.3.15-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libhivex-ocaml', 'pkgver': '1.3.15-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libhivex-ocaml-dev', 'pkgver': '1.3.15-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libhivex0', 'pkgver': '1.3.15-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libwin-hivex-perl', 'pkgver': '1.3.15-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'python-hivex', 'pkgver': '1.3.15-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'python3-hivex', 'pkgver': '1.3.15-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'ruby-hivex', 'pkgver': '1.3.15-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libhivex-bin', 'pkgver': '1.3.18-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libhivex-dev', 'pkgver': '1.3.18-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libhivex-ocaml', 'pkgver': '1.3.18-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libhivex-ocaml-dev', 'pkgver': '1.3.18-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libhivex0', 'pkgver': '1.3.18-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libwin-hivex-perl', 'pkgver': '1.3.18-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'python3-hivex', 'pkgver': '1.3.18-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'ruby-hivex', 'pkgver': '1.3.18-2ubuntu0.1'},
    {'osver': '21.04', 'pkgname': 'libhivex-bin', 'pkgver': '1.3.19-1ubuntu3.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libhivex-dev', 'pkgver': '1.3.19-1ubuntu3.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libhivex-ocaml', 'pkgver': '1.3.19-1ubuntu3.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libhivex-ocaml-dev', 'pkgver': '1.3.19-1ubuntu3.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libhivex0', 'pkgver': '1.3.19-1ubuntu3.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libwin-hivex-perl', 'pkgver': '1.3.19-1ubuntu3.21.04.1'},
    {'osver': '21.04', 'pkgname': 'python3-hivex', 'pkgver': '1.3.19-1ubuntu3.21.04.1'},
    {'osver': '21.04', 'pkgname': 'ruby-hivex', 'pkgver': '1.3.19-1ubuntu3.21.04.1'},
    {'osver': '21.10', 'pkgname': 'libhivex-bin', 'pkgver': '1.3.19-1ubuntu3.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libhivex-dev', 'pkgver': '1.3.19-1ubuntu3.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libhivex-ocaml', 'pkgver': '1.3.19-1ubuntu3.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libhivex-ocaml-dev', 'pkgver': '1.3.19-1ubuntu3.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libhivex0', 'pkgver': '1.3.19-1ubuntu3.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libwin-hivex-perl', 'pkgver': '1.3.19-1ubuntu3.21.10.1'},
    {'osver': '21.10', 'pkgname': 'python3-hivex', 'pkgver': '1.3.19-1ubuntu3.21.10.1'},
    {'osver': '21.10', 'pkgname': 'ruby-hivex', 'pkgver': '1.3.19-1ubuntu3.21.10.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libhivex-bin / libhivex-dev / libhivex-ocaml / libhivex-ocaml-dev / etc');
}
