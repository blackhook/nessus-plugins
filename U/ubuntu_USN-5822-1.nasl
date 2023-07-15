#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5822-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170562);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2021-20251",
    "CVE-2022-3437",
    "CVE-2022-37966",
    "CVE-2022-37967",
    "CVE-2022-38023",
    "CVE-2022-42898",
    "CVE-2022-45141"
  );
  script_xref(name:"USN", value:"5822-1");
  script_xref(name:"IAVA", value:"2022-A-0447-S");
  script_xref(name:"IAVA", value:"2022-A-0495-S");
  script_xref(name:"IAVA", value:"2023-A-0004-S");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 22.10 : Samba vulnerabilities (USN-5822-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5822-1 advisory.

  - A heap-based buffer overflow vulnerability was found in Samba within the GSSAPI unwrap_des() and
    unwrap_des3() routines of Heimdal. The DES and Triple-DES decryption routines in the Heimdal GSSAPI
    library allow a length-limited write buffer overflow on malloc() allocated memory when presented with a
    maliciously small packet. This flaw allows a remote user to send specially crafted malicious data to the
    application, possibly resulting in a denial of service (DoS) attack. (CVE-2022-3437)

  - Windows Kerberos RC4-HMAC Elevation of Privilege Vulnerability. (CVE-2022-37966)

  - Windows Kerberos Elevation of Privilege Vulnerability. (CVE-2022-37967)

  - Netlogon RPC Elevation of Privilege Vulnerability. (CVE-2022-38023)

  - PAC parsing in MIT Kerberos 5 (aka krb5) before 1.19.4 and 1.20.x before 1.20.1 has integer overflows that
    may lead to remote code execution (in KDC, kadmind, or a GSS or Kerberos application server) on 32-bit
    platforms (which have a resultant heap-based buffer overflow), and cause a denial of service on other
    platforms. This occurs in krb5_pac_parse in lib/krb5/krb/pac.c. Heimdal before 7.7.1 has a similar bug.
    (CVE-2022-42898)

  - The vulnerability exists due to an error that allows an attacker to force the server so issue an rc4-hmac
    ticket encrypted tickets despite the target server supporting better encryption (eg aes256-cts-hmac-
    sha1-96). A remote attacker can perform an offline attack against the ticket encrypted with rc4-hmac and
    login as a privileged user. (CVE-2022-45141)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5822-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45141");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ldb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-ldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-ldb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:registry-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-common-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-dsdb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-vfs-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:smbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:winbind");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'ctdb', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'python3-samba', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'samba', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'samba-common', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'smbclient', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'winbind', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '22.04', 'pkgname': 'ctdb', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'python3-samba', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'samba', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'samba-common', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'smbclient', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'ctdb', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'ldb-tools', 'pkgver': '2:2.5.2+samba4.16.8-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'libldb-dev', 'pkgver': '2:2.5.2+samba4.16.8-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'libldb2', 'pkgver': '2:2.5.2+samba4.16.8-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'libsmbclient', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'libwbclient0', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'python3-ldb', 'pkgver': '2:2.5.2+samba4.16.8-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'python3-ldb-dev', 'pkgver': '2:2.5.2+samba4.16.8-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'python3-samba', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'registry-tools', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'samba', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'samba-common', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'samba-dev', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'samba-libs', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'smbclient', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'},
    {'osver': '22.10', 'pkgname': 'winbind', 'pkgver': '2:4.16.8+dfsg-0ubuntu1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / ldb-tools / libldb-dev / libldb2 / libnss-winbind / etc');
}
