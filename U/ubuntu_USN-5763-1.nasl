#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5763-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168470);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2021-33430",
    "CVE-2021-34141",
    "CVE-2021-41495",
    "CVE-2021-41496"
  );
  script_xref(name:"USN", value:"5763-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS : NumPy vulnerabilities (USN-5763-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-5763-1 advisory.

  - ** DISPUTED ** A Buffer Overflow vulnerability exists in NumPy 1.9.x in the PyArray_NewFromDescr_int
    function of ctors.c when specifying arrays of large dimensions (over 32) from Python code, which could let
    a malicious user cause a Denial of Service. NOTE: The vendor does not agree this is a vulneraility; In
    (very limited) circumstances a user may be able provoke the buffer overflow, the user is most likely
    already privileged to at least provoke denial of service by exhausting memory. Triggering this further
    requires the use of uncommon API (complicated structured dtypes), which is very unlikely to be available
    to an unprivileged user. (CVE-2021-33430)

  - An incomplete string comparison in the numpy.core component in NumPy before 1.22.0 allows attackers to
    trigger slightly incorrect copying by constructing specific string objects. NOTE: the vendor states that
    this reported code behavior is completely harmless. (CVE-2021-34141)

  - ** DISPUTED ** Null Pointer Dereference vulnerability exists in numpy.sort in NumPy < and 1.19 in the
    PyArray_DescrNew function due to missing return-value validation, which allows attackers to conduct DoS
    attacks by repetitively creating sort arrays. NOTE: While correct that validation is missing, an error can
    only occur due to an exhaustion of memory. If the user can exhaust memory, they are already privileged.
    Further, it should be practically impossible to construct an attack which can target the memory exhaustion
    to occur at exactly this place. (CVE-2021-41495)

  - ** DISPUTED ** Buffer overflow in the array_from_pyobj function of fortranobject.c in NumPy < 1.19, which
    allows attackers to conduct a Denial of Service attacks by carefully constructing an array with negative
    values. NOTE: The vendor does not agree this is a vulnerability; the negative dimensions can only be
    created by an already privileged user (or internally). (CVE-2021-41496)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5763-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected python3-numpy package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34141");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-41496");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-numpy");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'python3-numpy', 'pkgver': '1:1.17.4-5ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'python3-numpy', 'pkgver': '1:1.21.5-1ubuntu22.04.1'},
    {'osver': '22.10', 'pkgname': 'python3-numpy', 'pkgver': '1:1.21.5-1ubuntu22.10.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-numpy');
}
