#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4981-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150232);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-28651",
    "CVE-2021-28652",
    "CVE-2021-28662",
    "CVE-2021-31806",
    "CVE-2021-31807",
    "CVE-2021-31808",
    "CVE-2021-33620"
  );
  script_xref(name:"USN", value:"4981-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 : Squid vulnerabilities (USN-4981-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4981-1 advisory.

  - An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to a buffer-management bug, it
    allows a denial of service. When resolving a request with the urn: scheme, the parser leaks a small amount
    of memory. However, there is an unspecified attack methodology that can easily trigger a large amount of
    memory consumption. (CVE-2021-28651)

  - An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to incorrect parser validation, it
    allows a Denial of Service attack against the Cache Manager API. This allows a trusted client to trigger
    memory leaks that. over time, lead to a Denial of Service via an unspecified short query string. This
    attack is limited to clients with Cache Manager API access privilege. (CVE-2021-28652)

  - An issue was discovered in Squid 4.x before 4.15 and 5.x before 5.0.6. If a remote server sends a certain
    response header over HTTP or HTTPS, there is a denial of service. This header can plausibly occur in
    benign network traffic. (CVE-2021-28662)

  - An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to a memory-management bug, it is
    vulnerable to a Denial of Service attack (against all clients using the proxy) via HTTP Range request
    processing. (CVE-2021-31806)

  - An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to an input-validation bug, it is
    vulnerable to a Denial of Service attack (against all clients using the proxy). A client sends an HTTP
    Range request to trigger this. (CVE-2021-31808)

  - Squid before 4.15 and 5.x before 5.0.6 allows remote servers to cause a denial of service (affecting
    availability to all clients) via an HTTP response. The issue trigger is a header that can be expected to
    exist in HTTP traffic without any malicious intent by the server. (CVE-2021-33620)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4981-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28651");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-purge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squidclient");
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
    {'osver': '18.04', 'pkgname': 'squid', 'pkgver': '3.5.27-1ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'squid-cgi', 'pkgver': '3.5.27-1ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'squid-common', 'pkgver': '3.5.27-1ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'squid-purge', 'pkgver': '3.5.27-1ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'squid3', 'pkgver': '3.5.27-1ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'squidclient', 'pkgver': '3.5.27-1ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'squid', 'pkgver': '4.10-1ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'squid-cgi', 'pkgver': '4.10-1ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'squid-common', 'pkgver': '4.10-1ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'squid-purge', 'pkgver': '4.10-1ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'squidclient', 'pkgver': '4.10-1ubuntu1.4'},
    {'osver': '20.10', 'pkgname': 'squid', 'pkgver': '4.13-1ubuntu2.2'},
    {'osver': '20.10', 'pkgname': 'squid-cgi', 'pkgver': '4.13-1ubuntu2.2'},
    {'osver': '20.10', 'pkgname': 'squid-common', 'pkgver': '4.13-1ubuntu2.2'},
    {'osver': '20.10', 'pkgname': 'squid-purge', 'pkgver': '4.13-1ubuntu2.2'},
    {'osver': '20.10', 'pkgname': 'squidclient', 'pkgver': '4.13-1ubuntu2.2'},
    {'osver': '21.04', 'pkgname': 'squid', 'pkgver': '4.13-1ubuntu4.1'},
    {'osver': '21.04', 'pkgname': 'squid-cgi', 'pkgver': '4.13-1ubuntu4.1'},
    {'osver': '21.04', 'pkgname': 'squid-common', 'pkgver': '4.13-1ubuntu4.1'},
    {'osver': '21.04', 'pkgname': 'squid-purge', 'pkgver': '4.13-1ubuntu4.1'},
    {'osver': '21.04', 'pkgname': 'squidclient', 'pkgver': '4.13-1ubuntu4.1'}
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'squid / squid-cgi / squid-common / squid-purge / squid3 / squidclient');
}