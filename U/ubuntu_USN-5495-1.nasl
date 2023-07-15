##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5495-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162554);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-32205",
    "CVE-2022-32206",
    "CVE-2022-32207",
    "CVE-2022-32208"
  );
  script_xref(name:"USN", value:"5495-1");
  script_xref(name:"IAVA", value:"2022-A-0255-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS : curl vulnerabilities (USN-5495-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5495-1 advisory.

  - When curl < 7.84.0 saves cookies, alt-svc and hsts data to local files, it makes the operation atomic by
    finalizing the operation with a rename from a temporary name to the final target file name.In that rename
    operation, it might accidentally *widen* the permissions for the target file, leaving the updated file
    accessible to more users than intended. (CVE-2022-32207)

  - A malicious server can serve excessive amounts of `Set-Cookie:` headers in a HTTP response to curl and
    curl < 7.84.0 stores all of them. A sufficiently large amount of (big) cookies make subsequent HTTP
    requests to this, or other servers to which the cookies match, create requests that become larger than the
    threshold that curl uses internally to avoid sending crazy large requests (1048576 bytes) and instead
    returns an error.This denial state might remain for as long as the same cookies are kept, match and
    haven't expired. Due to cookie matching rules, a server on `foo.example.com` can set cookies that also
    would match for `bar.example.com`, making it it possible for a sister server to effectively cause a
    denial of service for a sibling site on the same second level domain using this method. (CVE-2022-32205)

  - curl < 7.84.0 supports chained HTTP compression algorithms, meaning that a serverresponse can be
    compressed multiple times and potentially with different algorithms. The number of acceptable links in
    this decompression chain was unbounded, allowing a malicious server to insert a virtually unlimited
    number of compression steps.The use of such a decompression chain could result in a malloc bomb,
    makingcurl end up spending enormous amounts of allocated heap memory, or trying toand returning out of
    memory errors. (CVE-2022-32206)

  - When curl < 7.84.0 does FTP transfers secured by krb5, it handles message verification failures wrongly.
    This flaw makes it possible for a Man-In-The-Middle attack to go unnoticed and even allows it to inject
    data to the client. (CVE-2022-32208)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5495-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32207");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4-gnutls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4-nss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4-openssl-dev");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'curl', 'pkgver': '7.58.0-2ubuntu3.19'},
    {'osver': '18.04', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.58.0-2ubuntu3.19'},
    {'osver': '18.04', 'pkgname': 'libcurl3-nss', 'pkgver': '7.58.0-2ubuntu3.19'},
    {'osver': '18.04', 'pkgname': 'libcurl4', 'pkgver': '7.58.0-2ubuntu3.19'},
    {'osver': '18.04', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.58.0-2ubuntu3.19'},
    {'osver': '18.04', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.58.0-2ubuntu3.19'},
    {'osver': '18.04', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.58.0-2ubuntu3.19'},
    {'osver': '20.04', 'pkgname': 'curl', 'pkgver': '7.68.0-1ubuntu2.12'},
    {'osver': '20.04', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.68.0-1ubuntu2.12'},
    {'osver': '20.04', 'pkgname': 'libcurl3-nss', 'pkgver': '7.68.0-1ubuntu2.12'},
    {'osver': '20.04', 'pkgname': 'libcurl4', 'pkgver': '7.68.0-1ubuntu2.12'},
    {'osver': '20.04', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.68.0-1ubuntu2.12'},
    {'osver': '20.04', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.68.0-1ubuntu2.12'},
    {'osver': '20.04', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.68.0-1ubuntu2.12'},
    {'osver': '21.10', 'pkgname': 'curl', 'pkgver': '7.74.0-1.3ubuntu2.3'},
    {'osver': '21.10', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.74.0-1.3ubuntu2.3'},
    {'osver': '21.10', 'pkgname': 'libcurl3-nss', 'pkgver': '7.74.0-1.3ubuntu2.3'},
    {'osver': '21.10', 'pkgname': 'libcurl4', 'pkgver': '7.74.0-1.3ubuntu2.3'},
    {'osver': '21.10', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.74.0-1.3ubuntu2.3'},
    {'osver': '21.10', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.74.0-1.3ubuntu2.3'},
    {'osver': '21.10', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.74.0-1.3ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'curl', 'pkgver': '7.81.0-1ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.81.0-1ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'libcurl3-nss', 'pkgver': '7.81.0-1ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'libcurl4', 'pkgver': '7.81.0-1ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.81.0-1ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.81.0-1ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.81.0-1ubuntu1.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl / libcurl3-gnutls / libcurl3-nss / libcurl4 / etc');
}
