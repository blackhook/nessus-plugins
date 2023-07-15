#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5628-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165324);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2020-15106",
    "CVE-2020-15112",
    "CVE-2020-15113",
    "CVE-2020-15114"
  );
  script_xref(name:"USN", value:"5628-1");

  script_name(english:"Ubuntu 20.04 LTS : etcd vulnerabilities (USN-5628-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5628-1 advisory.

  - In etcd before versions 3.3.23 and 3.4.10, a large slice causes panic in decodeRecord method. The size of
    a record is stored in the length field of a WAL file and no additional validation is done on this data.
    Therefore, it is possible to forge an extremely large frame size that can unintentionally panic at the
    expense of any RAFT participant trying to decode the WAL. (CVE-2020-15106)

  - In etcd before versions 3.3.23 and 3.4.10, it is possible to have an entry index greater then the number
    of entries in the ReadAll method in wal/wal.go. This could cause issues when WAL entries are being read
    during consensus as an arbitrary etcd consensus participant could go down from a runtime panic when
    reading the entry. (CVE-2020-15112)

  - In etcd before versions 3.3.23 and 3.4.10, certain directory paths are created (etcd data directory and
    the directory path when provided to automatically generate self-signed certificates for TLS connections
    with clients) with restricted access permissions (700) by using the os.MkdirAll. This function does not
    perform any permission checks when a given directory path exists already. A possible workaround is to
    ensure the directories have the desired permission (700). (CVE-2020-15113)

  - In etcd before versions 3.3.23 and 3.4.10, the etcd gateway is a simple TCP proxy to allow for basic
    service discovery and access. However, it is possible to include the gateway address as an endpoint. This
    results in a denial of service, since the endpoint can become stuck in a loop of requesting itself until
    there are no more available file descriptors to accept connections on the gateway. (CVE-2020-15114)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5628-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15113");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:etcd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:etcd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:etcd-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-etcd-server-dev");
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
if (! ('20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'etcd', 'pkgver': '3.2.26+dfsg-6ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'etcd-client', 'pkgver': '3.2.26+dfsg-6ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'etcd-server', 'pkgver': '3.2.26+dfsg-6ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'golang-etcd-server-dev', 'pkgver': '3.2.26+dfsg-6ubuntu0.1'}
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
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'etcd / etcd-client / etcd-server / golang-etcd-server-dev');
}
