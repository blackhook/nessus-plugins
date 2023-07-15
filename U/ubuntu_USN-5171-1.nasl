#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5171-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155943);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2017-8844",
    "CVE-2017-8846",
    "CVE-2017-9928",
    "CVE-2017-9929",
    "CVE-2018-5650",
    "CVE-2018-5747",
    "CVE-2018-5786",
    "CVE-2018-9058",
    "CVE-2018-10685",
    "CVE-2018-11496"
  );
  script_xref(name:"USN", value:"5171-1");

  script_name(english:"Ubuntu 18.04 LTS : Long Range ZIP vulnerabilities (USN-5171-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-5171-1 advisory.

  - The read_1g function in stream.c in liblrzip.so in lrzip 0.631 allows remote attackers to cause a denial
    of service (heap-based buffer overflow and application crash) or possibly have unspecified other impact
    via a crafted archive. (CVE-2017-8844)

  - The read_stream function in stream.c in liblrzip.so in lrzip 0.631 allows remote attackers to cause a
    denial of service (use-after-free and application crash) via a crafted archive. (CVE-2017-8846)

  - In lrzip 0.631, a stack buffer overflow was found in the function get_fileinfo in lrzip.c:979, which
    allows attackers to cause a denial of service via a crafted file. (CVE-2017-9928)

  - In lrzip 0.631, a stack buffer overflow was found in the function get_fileinfo in lrzip.c:1074, which
    allows attackers to cause a denial of service via a crafted file. (CVE-2017-9929)

  - In Long Range Zip (aka lrzip) 0.631, there is an infinite loop and application hang in the unzip_match
    function in runzip.c. Remote attackers could leverage this vulnerability to cause a denial of service via
    a crafted lrz file. (CVE-2018-5650)

  - In Long Range Zip (aka lrzip) 0.631, there is a use-after-free in the ucompthread function (stream.c).
    Remote attackers could leverage this vulnerability to cause a denial of service via a crafted lrz file.
    (CVE-2018-5747)

  - In Long Range Zip (aka lrzip) 0.631, there is an infinite loop and application hang in the get_fileinfo
    function (lrzip.c). Remote attackers could leverage this vulnerability to cause a denial of service via a
    crafted lrz file. (CVE-2018-5786)

  - In Long Range Zip (aka lrzip) 0.631, there is a use-after-free in the lzma_decompress_buf function of
    stream.c, which allows remote attackers to cause a denial of service (application crash) or possibly have
    unspecified other impact. (CVE-2018-10685)

  - In Long Range Zip (aka lrzip) 0.631, there is a use-after-free in read_stream in stream.c, because
    decompress_file in lrzip.c lacks certain size validation. (CVE-2018-11496)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5171-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected lrzip package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10685");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lrzip");
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
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'lrzip', 'pkgver': '0.631-1+deb9u1build0.18.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lrzip');
}
