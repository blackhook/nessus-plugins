#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5260-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157286);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2021-43566", "CVE-2021-44142", "CVE-2022-0336");
  script_xref(name:"USN", value:"5260-1");
  script_xref(name:"IAVA", value:"2022-A-0054-S");
  script_xref(name:"IAVA", value:"2022-A-0020-S");

  script_name(english:"Ubuntu 20.04 LTS / 21.10 : Samba vulnerabilities (USN-5260-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 21.10 host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5260-1 advisory.

  - The Samba vfs_fruit module uses extended file attributes (EA, xattr) to provide ...enhanced compatibility
    with Apple SMB clients and interoperability with a Netatalk 3 AFP fileserver. Samba versions prior to
    4.13.17, 4.14.12 and 4.15.5 with vfs_fruit configured allow out-of-bounds heap read and write via
    specially crafted extended file attributes. A remote attacker with write access to extended file
    attributes can execute arbitrary code with the privileges of smbd, typically root. (CVE-2021-44142)

  - All versions of Samba prior to 4.13.16 are vulnerable to a malicious client using an SMB1 or NFS race to
    allow a directory to be created in an area of the server file system not exported under the share
    definition. Note that SMB1 has to be enabled, or the share also available via NFS in order for this attack
    to succeed. (CVE-2021-43566)

  - The Samba AD DC includes checks when adding service principals names (SPNs) to an account to ensure that
    SPNs do not alias with those already in the database. Some of these checks are able to be bypassed if an
    account modification re-adds an SPN that was previously present on that account, such as one added when a
    computer is joined to a domain. An attacker who has the ability to write to an account can exploit this to
    perform a denial-of-service attack by adding an SPN that matches an existing service. Additionally, an
    attacker who can intercept traffic can impersonate existing services, resulting in a loss of
    confidentiality and integrity. (CVE-2022-0336)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5260-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44142");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0336");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwbclient0");
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
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(20\.04|21\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 21.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '20.04', 'pkgname': 'ctdb', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'python3-samba', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'samba', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-common', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'smbclient', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '20.04', 'pkgname': 'winbind', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.10', 'pkgname': 'ctdb', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libsmbclient', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libwbclient0', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'python3-samba', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'registry-tools', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'samba', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'samba-common', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'samba-dev', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'samba-libs', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'smbclient', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'winbind', 'pkgver': '2:4.13.17~dfsg-0ubuntu0.21.10.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libnss-winbind / libpam-winbind / libsmbclient / etc');
}
