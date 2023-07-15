#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5906-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172050);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/19");

  script_cve_id("CVE-2022-41862");
  script_xref(name:"USN", value:"5906-1");
  script_xref(name:"IAVB", value:"2023-B-0009-S");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 22.10 : PostgreSQL vulnerability (USN-5906-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS host has packages installed that are affected by a vulnerability as referenced
in the USN-5906-1 advisory.

  - PostgreSQL Project reports:              A modified, unauthenticated server can send an
    unterminated string during the establishment of Kerberos             transport encryption. When a libpq
    client application             has a Kerberos credential cache and doesn't explicitly             disable
    option gssencmode, a server can cause libpq to             over-read and report an error message
    containing             uninitialized bytes from and following its receive             buffer. If libpq's
    caller somehow makes that message             accessible to the attacker, this achieves a disclosure
    of the over-read bytes. We have not confirmed or ruled             out viability of attacks that arrange
    for a crash or for             presence of notable, confidential information in             disclosed
    bytes.            (CVE-2022-41862)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5906-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41862");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-compat3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpgtypes3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython3-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython3-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"III");
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
if (! preg(pattern:"^(20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libecpg-compat3', 'pkgver': '12.14-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libecpg-dev', 'pkgver': '12.14-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libecpg6', 'pkgver': '12.14-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libpgtypes3', 'pkgver': '12.14-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libpq-dev', 'pkgver': '12.14-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libpq5', 'pkgver': '12.14-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-12', 'pkgver': '12.14-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-client-12', 'pkgver': '12.14-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-plperl-12', 'pkgver': '12.14-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-plpython3-12', 'pkgver': '12.14-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-pltcl-12', 'pkgver': '12.14-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-server-dev-12', 'pkgver': '12.14-0ubuntu0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'libecpg-compat3', 'pkgver': '14.7-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libecpg-dev', 'pkgver': '14.7-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libecpg6', 'pkgver': '14.7-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libpgtypes3', 'pkgver': '14.7-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libpq-dev', 'pkgver': '14.7-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libpq5', 'pkgver': '14.7-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'postgresql-14', 'pkgver': '14.7-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'postgresql-client-14', 'pkgver': '14.7-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'postgresql-plperl-14', 'pkgver': '14.7-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'postgresql-plpython3-14', 'pkgver': '14.7-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'postgresql-pltcl-14', 'pkgver': '14.7-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'postgresql-server-dev-14', 'pkgver': '14.7-0ubuntu0.22.04.1'},
    {'osver': '22.10', 'pkgname': 'libecpg-compat3', 'pkgver': '14.7-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libecpg-dev', 'pkgver': '14.7-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libecpg6', 'pkgver': '14.7-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libpgtypes3', 'pkgver': '14.7-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libpq-dev', 'pkgver': '14.7-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libpq5', 'pkgver': '14.7-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'postgresql-14', 'pkgver': '14.7-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'postgresql-client-14', 'pkgver': '14.7-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'postgresql-plperl-14', 'pkgver': '14.7-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'postgresql-plpython3-14', 'pkgver': '14.7-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'postgresql-pltcl-14', 'pkgver': '14.7-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'postgresql-server-dev-14', 'pkgver': '14.7-0ubuntu0.22.10.1'}
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
    severity   : SECURITY_NOTE,
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
