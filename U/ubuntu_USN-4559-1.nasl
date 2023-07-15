#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4559-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141112);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id("CVE-2020-1472");
  script_xref(name:"USN", value:"4559-1");
  script_xref(name:"IAVA", value:"2020-A-0438-S");
  script_xref(name:"IAVA", value:"0001-A-0647");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2020/09/21");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0101");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0008");
  script_xref(name:"CEA-ID", value:"CEA-2020-0121");
  script_xref(name:"CEA-ID", value:"CEA-2023-0016");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS : Samba update (USN-4559-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-4559-1 advisory.

  - An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure
    channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon
    Elevation of Privilege Vulnerability'. (CVE-2020-1472)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4559-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1472");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libparse-pidl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-samba");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'ctdb', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'libparse-pidl-perl', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'python-samba', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'samba', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'samba-common', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'smbclient', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '16.04', 'pkgname': 'winbind', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.31'},
    {'osver': '18.04', 'pkgname': 'ctdb', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'libparse-pidl-perl', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'python-samba', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'samba', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'samba-common', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'smbclient', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '18.04', 'pkgname': 'winbind', 'pkgver': '2:4.7.6+dfsg~ubuntu-0ubuntu2.20'},
    {'osver': '20.04', 'pkgname': 'ctdb', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'python3-samba', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'samba', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'samba-common', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'smbclient', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'winbind', 'pkgver': '2:4.11.6+dfsg-0ubuntu1.5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libnss-winbind / libpam-winbind / libparse-pidl-perl / etc');
}
