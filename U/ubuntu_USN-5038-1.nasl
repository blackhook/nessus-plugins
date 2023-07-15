#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5038-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152539);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-3449", "CVE-2021-3677");
  script_xref(name:"USN", value:"5038-1");
  script_xref(name:"IAVA", value:"2021-A-0149-S");
  script_xref(name:"IAVA", value:"2021-A-0193");
  script_xref(name:"IAVB", value:"2021-B-0048-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.04 : PostgreSQL vulnerabilities (USN-5038-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.04 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5038-1 advisory.

  - A flaw was found in postgresql. A purpose-crafted query can read arbitrary bytes of server memory. In the
    default configuration, any authenticated database user can complete this attack at will. The attack does
    not require the ability to create objects. If server settings include max_worker_processes=0, the known
    versions of this attack are infeasible. However, undiscovered variants of the attack may be independent of
    that setting. (CVE-2021-3677)

  - An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a
    client. If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was
    present in the initial ClientHello), but includes a signature_algorithms_cert extension then a NULL
    pointer dereference will result, leading to a crash and a denial of service attack. A server is only
    vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). OpenSSL TLS
    clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue. Users of
    these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in
    OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j). (CVE-2021-3449)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5038-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3677");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-compat3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpgtypes3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython3-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython3-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython3-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-13");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(18\.04|20\.04|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'libecpg-compat3', 'pkgver': '10.18-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libecpg-dev', 'pkgver': '10.18-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libecpg6', 'pkgver': '10.18-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libpgtypes3', 'pkgver': '10.18-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libpq-dev', 'pkgver': '10.18-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libpq5', 'pkgver': '10.18-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'postgresql-10', 'pkgver': '10.18-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'postgresql-client-10', 'pkgver': '10.18-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'postgresql-plperl-10', 'pkgver': '10.18-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'postgresql-plpython-10', 'pkgver': '10.18-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'postgresql-plpython3-10', 'pkgver': '10.18-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'postgresql-pltcl-10', 'pkgver': '10.18-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'postgresql-server-dev-10', 'pkgver': '10.18-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'libecpg-compat3', 'pkgver': '12.8-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libecpg-dev', 'pkgver': '12.8-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libecpg6', 'pkgver': '12.8-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libpgtypes3', 'pkgver': '12.8-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libpq-dev', 'pkgver': '12.8-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libpq5', 'pkgver': '12.8-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-12', 'pkgver': '12.8-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-client-12', 'pkgver': '12.8-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-plperl-12', 'pkgver': '12.8-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-plpython3-12', 'pkgver': '12.8-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-pltcl-12', 'pkgver': '12.8-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-server-dev-12', 'pkgver': '12.8-0ubuntu0.20.04.1'},
    {'osver': '21.04', 'pkgname': 'libecpg-compat3', 'pkgver': '13.4-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libecpg-dev', 'pkgver': '13.4-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libecpg6', 'pkgver': '13.4-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libpgtypes3', 'pkgver': '13.4-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libpq-dev', 'pkgver': '13.4-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libpq5', 'pkgver': '13.4-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'postgresql-13', 'pkgver': '13.4-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'postgresql-client-13', 'pkgver': '13.4-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'postgresql-plperl-13', 'pkgver': '13.4-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'postgresql-plpython3-13', 'pkgver': '13.4-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'postgresql-pltcl-13', 'pkgver': '13.4-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'postgresql-server-dev-13', 'pkgver': '13.4-0ubuntu0.21.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libecpg-compat3 / libecpg-dev / libecpg6 / libpgtypes3 / libpq-dev / etc');
}
