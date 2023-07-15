##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5142-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(155297);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2016-2124",
    "CVE-2020-25717",
    "CVE-2020-25718",
    "CVE-2020-25719",
    "CVE-2020-25721",
    "CVE-2020-25722",
    "CVE-2021-3671",
    "CVE-2021-3738",
    "CVE-2021-23192"
  );
  script_xref(name:"USN", value:"5142-1");
  script_xref(name:"IAVA", value:"2021-A-0554-S");

  script_name(english:"Ubuntu 20.04 LTS / 21.04 / 21.10 : Samba vulnerabilities (USN-5142-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 21.04 / 21.10 host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5142-1 advisory.

  - A flaw was found in the way Samba, as an Active Directory Domain Controller, implemented Kerberos name-
    based authentication. The Samba AD DC, could become confused about the user a ticket represents if it did
    not strictly require a Kerberos PAC and always use the SIDs found within. The result could include total
    domain compromise. (CVE-2020-25719)

  - A flaw was found in the way samba implemented SMB1 authentication. An attacker could use this flaw to
    retrieve the plaintext password sent over the wire even if Kerberos authentication was required.
    (CVE-2016-2124)

  - A flaw was found in the way Samba maps domain users to local users. An authenticated attacker could use
    this flaw to cause possible privilege escalation. (CVE-2020-25717)

  - A flaw was found in the way samba, as an Active Directory Domain Controller, is able to support an RODC
    (read-only domain controller). This would allow an RODC to print administrator tickets. (CVE-2020-25718)

  - Kerberos acceptors need easy access to stable AD identifiers (eg objectSid). Samba as an AD DC now
    provides a way for Linux applications to obtain a reliable SID (and samAccountName) in issued tickets.
    (CVE-2020-25721)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5142-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25719");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3738");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(20\.04|21\.04|21\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 21.04 / 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'ctdb', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'python3-samba', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'samba', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-common', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'smbclient', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'winbind', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.20.04.1'},
    {'osver': '21.04', 'pkgname': 'ctdb', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'python3-samba', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'samba', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'samba-common', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'smbclient', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'winbind', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.04.1'},
    {'osver': '21.10', 'pkgname': 'ctdb', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libsmbclient', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libwbclient0', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'python3-samba', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'registry-tools', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'samba', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'samba-common', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'samba-dev', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'samba-libs', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'smbclient', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'winbind', 'pkgver': '2:4.13.14+dfsg-0ubuntu0.21.10.1'}
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
