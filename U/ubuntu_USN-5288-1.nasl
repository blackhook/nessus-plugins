#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5288-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158212);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2021-45960",
    "CVE-2021-46143",
    "CVE-2022-22822",
    "CVE-2022-22823",
    "CVE-2022-22824",
    "CVE-2022-22825",
    "CVE-2022-22826",
    "CVE-2022-22827",
    "CVE-2022-23852",
    "CVE-2022-23990",
    "CVE-2022-25235",
    "CVE-2022-25236"
  );
  script_xref(name:"USN", value:"5288-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 21.10 : Expat vulnerabilities (USN-5288-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 21.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5288-1 advisory.

  - In Expat (aka libexpat) before 2.4.3, a left shift by 29 (or more) places in the storeAtts function in
    xmlparse.c can lead to realloc misbehavior (e.g., allocating too few bytes, or only freeing memory).
    (CVE-2021-45960)

  - In doProlog in xmlparse.c in Expat (aka libexpat) before 2.4.3, an integer overflow exists for
    m_groupSize. (CVE-2021-46143)

  - addBinding in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow. (CVE-2022-22822)

  - build_model in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow. (CVE-2022-22823)

  - defineAttribute in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.
    (CVE-2022-22824)

  - lookup in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow. (CVE-2022-22825)

  - nextScaffoldPart in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.
    (CVE-2022-22826)

  - storeAtts in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow. (CVE-2022-22827)

  - Expat (aka libexpat) before 2.4.4 has a signed integer overflow in XML_GetBuffer, for configurations with
    a nonzero XML_CONTEXT_BYTES. (CVE-2022-23852)

  - Expat (aka libexpat) before 2.4.4 has an integer overflow in the doProlog function. (CVE-2022-23990)

  - xmltok_impl.c in Expat (aka libexpat) before 2.4.5 lacks certain validation of encoding, such as checks
    for whether a UTF-8 character is valid in a certain context. (CVE-2022-25235)

  - xmlparse.c in Expat (aka libexpat) before 2.4.5 allows attackers to insert namespace-separator characters
    into namespace URIs. (CVE-2022-25236)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5288-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45960");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-25236");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:expat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64expat1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64expat1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexpat1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexpat1-dev");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'expat', 'pkgver': '2.1.0-7ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64expat1', 'pkgver': '2.1.0-7ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64expat1-dev', 'pkgver': '2.1.0-7ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'libexpat1', 'pkgver': '2.1.0-7ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'libexpat1-dev', 'pkgver': '2.1.0-7ubuntu0.16.04.5+esm2'},
    {'osver': '18.04', 'pkgname': 'expat', 'pkgver': '2.2.5-3ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'libexpat1', 'pkgver': '2.2.5-3ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'libexpat1-dev', 'pkgver': '2.2.5-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'expat', 'pkgver': '2.2.9-1ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libexpat1', 'pkgver': '2.2.9-1ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libexpat1-dev', 'pkgver': '2.2.9-1ubuntu0.2'},
    {'osver': '21.10', 'pkgname': 'expat', 'pkgver': '2.4.1-2ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libexpat1', 'pkgver': '2.4.1-2ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libexpat1-dev', 'pkgver': '2.4.1-2ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'expat / lib64expat1 / lib64expat1-dev / libexpat1 / libexpat1-dev');
}
