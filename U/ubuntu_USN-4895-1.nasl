##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4895-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148218);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-15049", "CVE-2020-25097");
  script_xref(name:"USN", value:"4895-1");
  script_xref(name:"IAVB", value:"2021-B-0021");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : Squid vulnerabilities (USN-4895-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4895-1 advisory.

  - An issue was discovered in http/ContentLengthInterpreter.cc in Squid before 4.12 and 5.x before 5.0.3. A
    Request Smuggling and Poisoning attack can succeed against the HTTP cache. The client sends an HTTP
    request with a Content-Length header containing +\ - or an uncommon shell whitespace character prefix
    to the length field-value. (CVE-2020-15049)

  - An issue was discovered in Squid through 4.13 and 5.x through 5.0.4. Due to improper input validation, it
    allows a trusted client to perform HTTP Request Smuggling and access services otherwise forbidden by the
    security controls. This occurs for certain uri_whitespace configuration settings. (CVE-2020-25097)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4895-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15049");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-purge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squidclient");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'squid', 'pkgver': '3.5.12-1ubuntu7.16'},
    {'osver': '16.04', 'pkgname': 'squid-cgi', 'pkgver': '3.5.12-1ubuntu7.16'},
    {'osver': '16.04', 'pkgname': 'squid-common', 'pkgver': '3.5.12-1ubuntu7.16'},
    {'osver': '16.04', 'pkgname': 'squid-purge', 'pkgver': '3.5.12-1ubuntu7.16'},
    {'osver': '16.04', 'pkgname': 'squid3', 'pkgver': '3.5.12-1ubuntu7.16'},
    {'osver': '16.04', 'pkgname': 'squidclient', 'pkgver': '3.5.12-1ubuntu7.16'},
    {'osver': '18.04', 'pkgname': 'squid', 'pkgver': '3.5.27-1ubuntu1.10'},
    {'osver': '18.04', 'pkgname': 'squid-cgi', 'pkgver': '3.5.27-1ubuntu1.10'},
    {'osver': '18.04', 'pkgname': 'squid-common', 'pkgver': '3.5.27-1ubuntu1.10'},
    {'osver': '18.04', 'pkgname': 'squid-purge', 'pkgver': '3.5.27-1ubuntu1.10'},
    {'osver': '18.04', 'pkgname': 'squid3', 'pkgver': '3.5.27-1ubuntu1.10'},
    {'osver': '18.04', 'pkgname': 'squidclient', 'pkgver': '3.5.27-1ubuntu1.10'},
    {'osver': '20.04', 'pkgname': 'squid', 'pkgver': '4.10-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'squid-cgi', 'pkgver': '4.10-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'squid-common', 'pkgver': '4.10-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'squid-purge', 'pkgver': '4.10-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'squidclient', 'pkgver': '4.10-1ubuntu1.3'},
    {'osver': '20.10', 'pkgname': 'squid', 'pkgver': '4.13-1ubuntu2.1'},
    {'osver': '20.10', 'pkgname': 'squid-cgi', 'pkgver': '4.13-1ubuntu2.1'},
    {'osver': '20.10', 'pkgname': 'squid-common', 'pkgver': '4.13-1ubuntu2.1'},
    {'osver': '20.10', 'pkgname': 'squid-purge', 'pkgver': '4.13-1ubuntu2.1'},
    {'osver': '20.10', 'pkgname': 'squidclient', 'pkgver': '4.13-1ubuntu2.1'}
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
