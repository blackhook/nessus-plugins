#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5864-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171392);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/13");

  script_cve_id(
    "CVE-2019-14275",
    "CVE-2019-19555",
    "CVE-2019-19797",
    "CVE-2020-21529",
    "CVE-2020-21530",
    "CVE-2020-21531",
    "CVE-2020-21532",
    "CVE-2020-21533",
    "CVE-2020-21534",
    "CVE-2020-21535",
    "CVE-2020-21675",
    "CVE-2020-21676",
    "CVE-2021-3561",
    "CVE-2021-32280"
  );
  script_xref(name:"USN", value:"5864-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Fig2dev vulnerabilities (USN-5864-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5864-1 advisory.

  - Xfig fig2dev 3.2.7a has a stack-based buffer overflow in the calc_arrow function in bound.c.
    (CVE-2019-14275)

  - read_textobject in read.c in Xfig fig2dev 3.2.7b has a stack-based buffer overflow because of an incorrect
    sscanf. (CVE-2019-19555)

  - read_colordef in read.c in Xfig fig2dev 3.2.7b has an out-of-bounds write. (CVE-2019-19797)

  - fig2dev 3.2.7b contains a stack buffer overflow in the bezier_spline function in genepic.c.
    (CVE-2020-21529)

  - fig2dev 3.2.7b contains a segmentation fault in the read_objects function in read.c. (CVE-2020-21530)

  - fig2dev 3.2.7b contains a global buffer overflow in the conv_pattern_index function in gencgm.c.
    (CVE-2020-21531)

  - fig2dev 3.2.7b contains a global buffer overflow in the setfigfont function in genepic.c. (CVE-2020-21532)

  - fig2dev 3.2.7b contains a stack buffer overflow in the read_textobject function in read.c.
    (CVE-2020-21533)

  - fig2dev 3.2.7b contains a global buffer overflow in the get_line function in read.c. (CVE-2020-21534)

  - fig2dev 3.2.7b contains a segmentation fault in the gencgm_start function in gencgm.c. (CVE-2020-21535)

  - A stack-based buffer overflow in the genptk_text component in genptk.c of fig2dev 3.2.7b allows attackers
    to cause a denial of service (DOS) via converting a xfig file into ptk format. (CVE-2020-21675)

  - A stack-based buffer overflow in the genpstrx_text() component in genpstricks.c of fig2dev 3.2.7b allows
    attackers to cause a denial of service (DOS) via converting a xfig file into pstricks format.
    (CVE-2020-21676)

  - An Out of Bounds flaw was found fig2dev version 3.2.8a. A flawed bounds check in read_objects() could
    allow an attacker to provide a crafted malicious input causing the application to either crash or in some
    cases cause memory corruption. The highest threat from this vulnerability is to integrity as well as
    system availability. (CVE-2021-3561)

  - An issue was discovered in fig2dev before 3.2.8.. A NULL pointer dereference exists in the function
    compute_closed_spline() located in trans_spline.c. It allows an attacker to cause Denial of Service. The
    fixed version of fig2dev is 3.2.8. (CVE-2021-32280)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5864-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected fig2dev and / or transfig packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3561");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fig2dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:transfig");
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
if (! preg(pattern:"^(18\.04|20\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'fig2dev', 'pkgver': '1:3.2.6a-6ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'transfig', 'pkgver': '1:3.2.6a-6ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'fig2dev', 'pkgver': '1:3.2.7a-7ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fig2dev / transfig');
}
