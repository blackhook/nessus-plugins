##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4633-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142968);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-25694", "CVE-2020-25695", "CVE-2020-25696");
  script_xref(name:"USN", value:"4633-1");
  script_xref(name:"IAVB", value:"2020-B-0069-S");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : PostgreSQL vulnerabilities (USN-4633-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4633-1 advisory.

  - A flaw was found in PostgreSQL versions before 13.1, before 12.5, before 11.10, before 10.15, before
    9.6.20 and before 9.5.24. If a client application that creates additional database connections only reuses
    the basic connection parameters while dropping security-relevant parameters, an opportunity for a man-in-
    the-middle attack, or the ability to observe clear-text transmissions, could exist. The highest threat
    from this vulnerability is to data confidentiality and integrity as well as system availability.
    (CVE-2020-25694)

  - A flaw was found in PostgreSQL versions before 13.1, before 12.5, before 11.10, before 10.15, before
    9.6.20 and before 9.5.24. An attacker having permission to create non-temporary objects in at least one
    schema can execute arbitrary SQL functions under the identity of a superuser. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability. (CVE-2020-25695)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4633-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25696");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-25695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-compat3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpgtypes3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-9.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-9.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-contrib-9.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-9.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython-9.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython3-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython3-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython3-9.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-9.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-9.5");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'libecpg-compat3', 'pkgver': '9.5.24-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libecpg-dev', 'pkgver': '9.5.24-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libecpg6', 'pkgver': '9.5.24-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libpgtypes3', 'pkgver': '9.5.24-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libpq-dev', 'pkgver': '9.5.24-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libpq5', 'pkgver': '9.5.24-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'postgresql-9.5', 'pkgver': '9.5.24-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'postgresql-client-9.5', 'pkgver': '9.5.24-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'postgresql-contrib-9.5', 'pkgver': '9.5.24-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'postgresql-plperl-9.5', 'pkgver': '9.5.24-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'postgresql-plpython-9.5', 'pkgver': '9.5.24-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'postgresql-plpython3-9.5', 'pkgver': '9.5.24-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'postgresql-pltcl-9.5', 'pkgver': '9.5.24-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'postgresql-server-dev-9.5', 'pkgver': '9.5.24-0ubuntu0.16.04.1'},
    {'osver': '18.04', 'pkgname': 'libecpg-compat3', 'pkgver': '10.15-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libecpg-dev', 'pkgver': '10.15-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libecpg6', 'pkgver': '10.15-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libpgtypes3', 'pkgver': '10.15-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libpq-dev', 'pkgver': '10.15-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libpq5', 'pkgver': '10.15-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'postgresql-10', 'pkgver': '10.15-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'postgresql-client-10', 'pkgver': '10.15-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'postgresql-plperl-10', 'pkgver': '10.15-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'postgresql-plpython-10', 'pkgver': '10.15-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'postgresql-plpython3-10', 'pkgver': '10.15-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'postgresql-pltcl-10', 'pkgver': '10.15-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'postgresql-server-dev-10', 'pkgver': '10.15-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'libecpg-compat3', 'pkgver': '12.5-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libecpg-dev', 'pkgver': '12.5-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libecpg6', 'pkgver': '12.5-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libpgtypes3', 'pkgver': '12.5-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libpq-dev', 'pkgver': '12.5-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libpq5', 'pkgver': '12.5-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-12', 'pkgver': '12.5-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-client-12', 'pkgver': '12.5-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-plperl-12', 'pkgver': '12.5-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-plpython3-12', 'pkgver': '12.5-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-pltcl-12', 'pkgver': '12.5-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'postgresql-server-dev-12', 'pkgver': '12.5-0ubuntu0.20.04.1'},
    {'osver': '20.10', 'pkgname': 'libecpg-compat3', 'pkgver': '12.5-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libecpg-dev', 'pkgver': '12.5-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libecpg6', 'pkgver': '12.5-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libpgtypes3', 'pkgver': '12.5-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libpq-dev', 'pkgver': '12.5-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libpq5', 'pkgver': '12.5-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'postgresql-12', 'pkgver': '12.5-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'postgresql-client-12', 'pkgver': '12.5-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'postgresql-plperl-12', 'pkgver': '12.5-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'postgresql-plpython3-12', 'pkgver': '12.5-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'postgresql-pltcl-12', 'pkgver': '12.5-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'postgresql-server-dev-12', 'pkgver': '12.5-0ubuntu0.20.10.1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libecpg-compat3 / libecpg-dev / libecpg6 / libpgtypes3 / libpq-dev / etc');
}
