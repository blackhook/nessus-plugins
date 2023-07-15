#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4998-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151000);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-25678",
    "CVE-2020-27781",
    "CVE-2020-27839",
    "CVE-2021-3509",
    "CVE-2021-3524",
    "CVE-2021-3531",
    "CVE-2021-20288"
  );
  script_xref(name:"USN", value:"4998-1");

  script_name(english:"Ubuntu 20.04 LTS : Ceph vulnerabilities (USN-4998-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4998-1 advisory.

  - A flaw was found in ceph in versions prior to 16.y.z where ceph stores mgr module passwords in clear text.
    This can be found by searching the mgr logs for grafana and dashboard, with passwords visible.
    (CVE-2020-25678)

  - User credentials can be manipulated and stolen by Native CephFS consumers of OpenStack Manila, resulting
    in potential privilege escalation. An Open Stack Manila user can request access to a share to an arbitrary
    cephx user, including existing users. The access key is retrieved via the interface drivers. Then, all
    users of the requesting OpenStack project can view the access key. This enables the attacker to target any
    resource that the user has access to. This can be done to even admin users, compromising the ceph
    administrator. This flaw affects Ceph versions prior to 14.2.16, 15.x prior to 15.2.8, and 16.x prior to
    16.2.0. (CVE-2020-27781)

  - A flaw was found in ceph-dashboard. The JSON Web Token (JWT) used for user authentication is stored by the
    frontend application in the browsers localStorage which is potentially vulnerable to attackers via XSS
    attacks. The highest threat from this vulnerability is to data confidentiality and integrity.
    (CVE-2020-27839)

  - A flaw was found in Red Hat Ceph Storage 4, in the Dashboard component. In response to CVE-2020-27839, the
    JWT token was moved from localStorage to an httpOnly cookie. However, token cookies are used in the body
    of the HTTP response for the documentation, which again makes it available to XSS.The greatest threat to
    the system is for confidentiality, integrity, and availability. (CVE-2021-3509)

  - A flaw was found in the Red Hat Ceph Storage RadosGW (Ceph Object Gateway) in versions before 14.2.21. The
    vulnerability is related to the injection of HTTP headers via a CORS ExposeHeader tag. The newline
    character in the ExposeHeader tag in the CORS configuration file generates a header injection in the
    response when the CORS request is made. In addition, the prior bug fix for CVE-2020-10753 did not account
    for the use of \r as a header separator, thus a new flaw has been created. (CVE-2021-3524)

  - A flaw was found in the Red Hat Ceph Storage RGW in versions before 14.2.21. When processing a GET Request
    for a swift URL that ends with two slashes it can cause the rgw to crash, resulting in a denial of
    service. The greatest threat to the system is of availability. (CVE-2021-3531)

  - An authentication flaw was found in ceph in versions before 14.2.20. When the monitor handles
    CEPHX_GET_AUTH_SESSION_KEY requests, it doesn't sanitize other_keys, allowing key reuse. An attacker who
    can request a global_id can exploit the ability of any user to request a global_id previously associated
    with another user, as ceph does not force the reuse of old keys to generate new ones. The highest threat
    from this vulnerability is to data confidentiality and integrity as well as system availability.
    (CVE-2021-20288)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4998-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20288");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-immutable-object-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-dashboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-diskprediction-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-diskprediction-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-k8sevents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-rook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cephfs-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librados-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libradospp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libradosstriper-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librbd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librgw-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rados-objclass-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rbd-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rbd-nbd");
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
if (! preg(pattern:"^(20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '20.04', 'pkgname': 'ceph', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'ceph-base', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'ceph-common', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'ceph-fuse', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'ceph-immutable-object-cache', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'ceph-mds', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-cephadm', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-dashboard', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-diskprediction-cloud', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-diskprediction-local', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-k8sevents', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-modules-core', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-rook', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'ceph-mon', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'ceph-osd', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'ceph-resource-agents', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'cephadm', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'cephfs-shell', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libcephfs-dev', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libcephfs-java', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libcephfs-jni', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libcephfs2', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librados-dev', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librados2', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libradospp-dev', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libradosstriper-dev', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libradosstriper1', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librbd-dev', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librbd1', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librgw-dev', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librgw2', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'python3-ceph', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'python3-ceph-argparse', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'python3-ceph-common', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'python3-cephfs', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'python3-rados', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'python3-rbd', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'python3-rgw', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'rados-objclass-dev', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'radosgw', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'rbd-fuse', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'rbd-mirror', 'pkgver': '15.2.12-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'rbd-nbd', 'pkgver': '15.2.12-0ubuntu0.20.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph / ceph-base / ceph-common / ceph-fuse / etc');
}
