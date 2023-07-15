#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5658-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165706);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-2928", "CVE-2022-2929");
  script_xref(name:"USN", value:"5658-1");
  script_xref(name:"IAVB", value:"2022-B-0037");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : DHCP vulnerabilities (USN-5658-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5658-1 advisory.

  - In ISC DHCP 1.0 -> 4.4.3, ISC DHCP 4.1-ESV-R1 -> 4.1-ESV-R16-P1 a system with access to a DHCP server,
    sending DHCP packets crafted to include fqdn labels longer than 63 bytes, could eventually cause the
    server to run out of memory. (CVE-2022-2929)

  - In ISC DHCP 4.4.0 -> 4.4.3, ISC DHCP 4.1-ESV-R1 -> 4.1-ESV-R16-P1, when the function
    option_code_hash_lookup() is called from add_option(), it increases the option's refcount field. However,
    there is not a corresponding call to option_dereference() to decrement the refcount field. The function
    add_option() is only used in server responses to lease query packets. Each lease query response calls this
    function for several options, so eventually, the reference counters could overflow and cause the server to
    abort. (CVE-2022-2928)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5658-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2929");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-client-ddns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-server-ldap");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'isc-dhcp-client', 'pkgver': '4.3.5-3ubuntu7.4'},
    {'osver': '18.04', 'pkgname': 'isc-dhcp-client-ddns', 'pkgver': '4.3.5-3ubuntu7.4'},
    {'osver': '18.04', 'pkgname': 'isc-dhcp-common', 'pkgver': '4.3.5-3ubuntu7.4'},
    {'osver': '18.04', 'pkgname': 'isc-dhcp-dev', 'pkgver': '4.3.5-3ubuntu7.4'},
    {'osver': '18.04', 'pkgname': 'isc-dhcp-relay', 'pkgver': '4.3.5-3ubuntu7.4'},
    {'osver': '18.04', 'pkgname': 'isc-dhcp-server', 'pkgver': '4.3.5-3ubuntu7.4'},
    {'osver': '18.04', 'pkgname': 'isc-dhcp-server-ldap', 'pkgver': '4.3.5-3ubuntu7.4'},
    {'osver': '20.04', 'pkgname': 'isc-dhcp-client', 'pkgver': '4.4.1-2.1ubuntu5.20.04.4'},
    {'osver': '20.04', 'pkgname': 'isc-dhcp-client-ddns', 'pkgver': '4.4.1-2.1ubuntu5.20.04.4'},
    {'osver': '20.04', 'pkgname': 'isc-dhcp-common', 'pkgver': '4.4.1-2.1ubuntu5.20.04.4'},
    {'osver': '20.04', 'pkgname': 'isc-dhcp-dev', 'pkgver': '4.4.1-2.1ubuntu5.20.04.4'},
    {'osver': '20.04', 'pkgname': 'isc-dhcp-relay', 'pkgver': '4.4.1-2.1ubuntu5.20.04.4'},
    {'osver': '20.04', 'pkgname': 'isc-dhcp-server', 'pkgver': '4.4.1-2.1ubuntu5.20.04.4'},
    {'osver': '20.04', 'pkgname': 'isc-dhcp-server-ldap', 'pkgver': '4.4.1-2.1ubuntu5.20.04.4'},
    {'osver': '22.04', 'pkgname': 'isc-dhcp-client', 'pkgver': '4.4.1-2.3ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'isc-dhcp-client-ddns', 'pkgver': '4.4.1-2.3ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'isc-dhcp-common', 'pkgver': '4.4.1-2.3ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'isc-dhcp-dev', 'pkgver': '4.4.1-2.3ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'isc-dhcp-relay', 'pkgver': '4.4.1-2.3ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'isc-dhcp-server', 'pkgver': '4.4.1-2.3ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'isc-dhcp-server-ldap', 'pkgver': '4.4.1-2.3ubuntu2.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'isc-dhcp-client / isc-dhcp-client-ddns / isc-dhcp-common / etc');
}
