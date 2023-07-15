#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4994-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150940);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-13950",
    "CVE-2020-35452",
    "CVE-2021-26690",
    "CVE-2021-26691",
    "CVE-2021-30641"
  );
  script_xref(name:"USN", value:"4994-1");
  script_xref(name:"IAVA", value:"2021-A-0259-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 : Apache HTTP Server vulnerabilities (USN-4994-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4994-1 advisory.

  - Apache HTTP Server versions 2.4.41 to 2.4.46 mod_proxy_http can be made to crash (NULL pointer
    dereference) with specially crafted requests using both Content-Length and Transfer-Encoding headers,
    leading to a Denial of Service (CVE-2020-13950)

  - Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Digest nonce can cause a stack overflow in
    mod_auth_digest. There is no report of this overflow being exploitable, nor the Apache HTTP Server team
    could create one, though some particular compiler and/or compilation option might make it possible, with
    limited consequences anyway due to the size (a single byte) and the value (zero byte) of the overflow
    (CVE-2020-35452)

  - Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Cookie header handled by mod_session can
    cause a NULL pointer dereference and crash, leading to a possible Denial Of Service (CVE-2021-26690)

  - In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionHeader sent by an origin server
    could cause a heap overflow (CVE-2021-26691)

  - Apache HTTP Server versions 2.4.39 to 2.4.46 Unexpected matching behavior with 'MergeSlashes OFF'
    (CVE-2021-30641)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4994-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26691");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-ssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec-pristine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-proxy-uwsgi");
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
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|20\.10|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 20.10 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'apache2', 'pkgver': '2.4.29-1ubuntu4.16'},
    {'osver': '18.04', 'pkgname': 'apache2-bin', 'pkgver': '2.4.29-1ubuntu4.16'},
    {'osver': '18.04', 'pkgname': 'apache2-data', 'pkgver': '2.4.29-1ubuntu4.16'},
    {'osver': '18.04', 'pkgname': 'apache2-dev', 'pkgver': '2.4.29-1ubuntu4.16'},
    {'osver': '18.04', 'pkgname': 'apache2-ssl-dev', 'pkgver': '2.4.29-1ubuntu4.16'},
    {'osver': '18.04', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.29-1ubuntu4.16'},
    {'osver': '18.04', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.29-1ubuntu4.16'},
    {'osver': '18.04', 'pkgname': 'apache2-utils', 'pkgver': '2.4.29-1ubuntu4.16'},
    {'osver': '20.04', 'pkgname': 'apache2', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'apache2-bin', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'apache2-data', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'apache2-dev', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'apache2-ssl-dev', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'apache2-utils', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'libapache2-mod-md', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'libapache2-mod-proxy-uwsgi', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.10', 'pkgname': 'apache2', 'pkgver': '2.4.46-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'apache2-bin', 'pkgver': '2.4.46-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'apache2-data', 'pkgver': '2.4.46-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'apache2-dev', 'pkgver': '2.4.46-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'apache2-ssl-dev', 'pkgver': '2.4.46-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.46-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.46-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'apache2-utils', 'pkgver': '2.4.46-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'libapache2-mod-md', 'pkgver': '2.4.46-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'libapache2-mod-proxy-uwsgi', 'pkgver': '2.4.46-1ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'apache2', 'pkgver': '2.4.46-4ubuntu1.1'},
    {'osver': '21.04', 'pkgname': 'apache2-bin', 'pkgver': '2.4.46-4ubuntu1.1'},
    {'osver': '21.04', 'pkgname': 'apache2-data', 'pkgver': '2.4.46-4ubuntu1.1'},
    {'osver': '21.04', 'pkgname': 'apache2-dev', 'pkgver': '2.4.46-4ubuntu1.1'},
    {'osver': '21.04', 'pkgname': 'apache2-ssl-dev', 'pkgver': '2.4.46-4ubuntu1.1'},
    {'osver': '21.04', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.46-4ubuntu1.1'},
    {'osver': '21.04', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.46-4ubuntu1.1'},
    {'osver': '21.04', 'pkgname': 'apache2-utils', 'pkgver': '2.4.46-4ubuntu1.1'},
    {'osver': '21.04', 'pkgname': 'libapache2-mod-md', 'pkgver': '2.4.46-4ubuntu1.1'},
    {'osver': '21.04', 'pkgname': 'libapache2-mod-proxy-uwsgi', 'pkgver': '2.4.46-4ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2 / apache2-bin / apache2-data / apache2-dev / apache2-ssl-dev / etc');
}
