##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5542-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163679);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2021-3670",
    "CVE-2022-2031",
    "CVE-2022-32742",
    "CVE-2022-32744",
    "CVE-2022-32745",
    "CVE-2022-32746"
  );
  script_xref(name:"USN", value:"5542-1");
  script_xref(name:"IAVA", value:"2022-A-0299-S");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS : Samba vulnerabilities (USN-5542-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5542-1 advisory.

  - samba: MaxQueryDuration not honoured in Samba AD DC LDAP (CVE-2021-3670)

  - The KDC and the kpasswd service share a single account and set of keys. In certain cases, this makes the
    two services susceptible to confusion. When a user's password has expired, that user is requested to
    change their password. Until doing so, the user is restricted to only acquiring tickets to kpasswd.
    However, a vulnerability meant that the kpasswd's principal, when canonicalized, was set to that of the
    TGS (Ticket-Granting Service), thus yielding TGTs from ordinary kpasswd requests. These TGTs could be used
    to perform an Elevation of Privilege attack by obtaining service tickets and using services in the forest.
    This vulnerability existed in versions of Samba built with Heimdal Kerberos. A separate vulnerability in
    Samba versions below 4.16, and in Samba built with MIT Kerberos, led the KDC to accept kpasswd tickets as
    if they were TGTs, with the same overall outcome. On the reverse side of the issue, password changes could
    be effected by presenting TGTs as if they were kpasswd tickets. TGTs having potentially longer lifetimes
    than kpasswd tickets, the value of a stolen cache containing a TGT was hence increased to an attacker,
    with the possibility of indefinite control over an account by means of a password change. Finally, kpasswd
    service tickets would be accepted for changes to one's own password, contrary to the requirement that
    tickets be acquired with an initial KDC request in such cases. As part of the mitigations, the lifetime of
    kpasswd tickets has been restricted to a maximum of two minutes. The KDC will not longer accept TGTs with
    two minutes or less left to live, to make sure it does not accept kpasswd tickets. (CVE-2022-2031)

  - Please note that only versions of Samba prior to 4.11.0 are vulnerable to this bug by default. Samba
    versions 4.11.0 and above disable SMB1 by default, and will only be vulnerable if the administrator has
    deliberately enabled SMB1 in the smb.conf file. All versions of Samba with SMB1 enabled are vulnerable to
    a server memory information leak bug over SMB1 if a client can write data to a share. Some SMB1 write
    requests were not correctly range checked to ensure the client had sent enough data to fulfill the write,
    allowing server memory contents to be written into the file (or printer) instead of client supplied data.
    The client cannot control the area of the server memory that is written to the file (or printer).
    (CVE-2022-32742)

  - Tickets received by the kpasswd service were decrypted without specifying that only that service's own
    keys should be tried. By setting the ticket's server name to a principal associated with their own
    account, or by exploiting a fallback where known keys would be tried until a suitable one was found, an
    attacker could have the server accept tickets encrypted with any key, including their own. A user could
    thus change the password of the Administrator account and gain total control over the domain. Full loss of
    confidentiality and integrity would be possible, as well as of availability by denying users access to
    their accounts. In addition, the kpasswd service would accept tickets encrypted by the krbtgt key of an
    RODC, in spite of the fact that RODCs should not have been able to authorise password changes.
    (CVE-2022-32744)

  - Due to incorrect values used as the limit for a loop and as the 'count' parameter to memcpy(), the server,
    receiving a specially crafted message, leaves an array of structures partially uninitialised, or accesses
    an arbitrary element beyond the end of an array. Outcomes achievable by an attacker include segmentation
    faults and corresponding loss of availability. Depending on the contents of the uninitialised memory,
    confidentiality may also be affected. (CVE-2022-32745)

  - Some database modules make a shallow copy of an LDAP add/delete message so they can make modifications to
    its elements without affecting the original message. Each element in a message points to an array of
    values, and these arrays are shared between the original message and the copy. The issue arises when a
    database module adds new values to an existing array. A call to realloc() increases the array's size to
    accommodate new elements, but at the same time, frees the old array. This leaves the original message
    element with a dangling pointer to a now-freed array. When the database audit logging module subsequently
    logs the details of the original message, it will access this freed data, generally resulting in corrupted
    log output or a crash. The code paths susceptible to this issue are reachable when certain specific
    attributes, such as userAccountControl, are added or modified. These attributes are not editable by
    default without having a privilege assigned, such as Write Property. (CVE-2022-32746)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5542-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32745");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32744");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
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

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'ctdb', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'python3-samba', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'samba', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-common', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'smbclient', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'winbind', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.1'},
    {'osver': '22.04', 'pkgname': 'ctdb', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'python3-samba', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'samba', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'samba-common', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'smbclient', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'winbind', 'pkgver': '2:4.15.9+dfsg-0ubuntu0.2'}
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
