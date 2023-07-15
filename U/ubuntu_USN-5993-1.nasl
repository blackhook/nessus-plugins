#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5993-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173794);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/11");

  script_cve_id("CVE-2023-0614", "CVE-2023-0922");
  script_xref(name:"IAVA", value:"2023-A-0167");
  script_xref(name:"USN", value:"5993-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 22.10 : Samba vulnerabilities (USN-5993-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5993-1 advisory.

  - In Active Directory, there are essentially four different classes of attributes. - Secret attributes (such
    as a user, computer or domain trust password) that are never disclosed and are not available to search
    against over LDAP. This is a hard-coded list, and since Samba 4.8 these are additionally encrypted in the
    DB with a per-DB key. - Confidential attributes (marked as such in the schema) that have a default access
    restriction allowing access only to the owner of the object. While a Samba AD Domain makes these
    attributes available, thankfully by default it will not have any of these confidential attributes set, as
    they are only added by clients after configuration (typically via a GPO). Examples of confidential data
    stored in Active Directory include BitLocker recovery keys, TPM owner passwords, and certificate secret
    keys stored with Credential Roaming. - Access controlled attributes (for reads or writes), Samba will
    honour the access control specified in the ntSecurityDescriptor. - Public attributes for read. Most
    attributes in Active Directory are available to read by all authenticated users. Because the access
    control rules for a given attribute are not consistent between objects, Samba implemented access control
    restrictions only after matching objects against the filter. Taking each of the above classes in turn: -
    Secret attributes are prevented from disclosure firstly by redaction of the LDAP filter, and secondly by
    the fact that they are still encrypted during filter processing (by default). - Confidential and access
    controlled attributes were subject to an attack using LDAP filters. With this security patch, for
    attributes mentioned in the search filter, Samba will perform a per-object access control evaluation
    before LDAP filter matching on the attribute, preventing unauthorised disclosure of the value of (for
    example) BitLocker recovery keys. It is not expected that all similar attacks have been prevented, and it
    is likely still possible to determine if an object or attribute on an object is present, but not to obtain
    the contents. (CVE-2023-0614)

  - Active Directory allows passwords to be set and changed over LDAP. Microsoft's implementation imposes a
    restriction that this may only happen over an encrypted connection, however Samba does not have this
    restriction currently. Samba's samba-tool client tool likewise has no restriction regarding the security
    of the connection it will set a password over. An attacker able to observe the network traffic between
    samba-tool and the Samba AD DC could obtain newly set passwords if samba-tool connected using a Kerberos
    secured LDAP connection against a Samba AD DC. This would happen when samba-tool was used to reset a
    user's password, or to add a new user. This only impacts connections made using Kerberos as NTLM-protected
    connections are upgraded to encryption regardless. This patch changes all Samba AD LDAP client connections
    to use encryption, as well as integrity protection, by default, by changing the default value of client
    ldap sasl wrapping to seal in Samba's smb.conf. Administrators should confirm this value has not been
    overridden in their local smb.conf to obtain the benefit of this change. NOTE WELL: Samba, for
    consistency, uses a common smb.conf option for LDAP client behaviour. Therefore this will also encrypt the
    AD LDAP connections between Samba's winbindd and any AD DC, so this patch will also change behaviour for
    Samba Domain Member configurations. If this is a concern, the smb.conf value client ldap sasl wrapping
    can be reset to sign. (CVE-2023-0922)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5993-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0614");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/03");

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
if (! preg(pattern:"^(20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'ctdb', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'python3-samba', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'samba', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'samba-common', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'smbclient', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '22.04', 'pkgname': 'ctdb', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'python3-samba', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'samba', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'samba-common', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'smbclient', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'ctdb', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'ldb-tools', 'pkgver': '2:2.5.3+samba4.16.8-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libldb-dev', 'pkgver': '2:2.5.3+samba4.16.8-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libldb2', 'pkgver': '2:2.5.3+samba4.16.8-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libsmbclient', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libwbclient0', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'python3-ldb', 'pkgver': '2:2.5.3+samba4.16.8-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'python3-ldb-dev', 'pkgver': '2:2.5.3+samba4.16.8-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'python3-samba', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'registry-tools', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'samba', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'samba-common', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'samba-dev', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'samba-libs', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'smbclient', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'winbind', 'pkgver': '2:4.16.8+dfsg-0ubuntu1.1'}
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
    severity   : SECURITY_WARNING,
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
