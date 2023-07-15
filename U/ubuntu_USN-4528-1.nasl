#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4528-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140730);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-1760", "CVE-2020-10753", "CVE-2020-12059");
  script_xref(name:"USN", value:"4528-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Ceph vulnerabilities (USN-4528-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4528-1 advisory.

  - A flaw was found in the Ceph Object Gateway, where it supports request sent by an anonymous user in Amazon
    S3. This flaw could lead to potential XSS attacks due to the lack of proper neutralization of untrusted
    input. (CVE-2020-1760)

  - A flaw was found in the Red Hat Ceph Storage RadosGW (Ceph Object Gateway). The vulnerability is related
    to the injection of HTTP headers via a CORS ExposeHeader tag. The newline character in the ExposeHeader
    tag in the CORS configuration file generates a header injection in the response when the CORS request is
    made. Ceph versions 3.x and 4.x are vulnerable to this issue. (CVE-2020-10753)

  - An issue was discovered in Ceph through 13.2.9. A POST request with an invalid tagging XML can crash the
    RGW process by triggering a NULL pointer exception. (CVE-2020-12059)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4528-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1760");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10753");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-fs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librados-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libradosstriper-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librbd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librgw-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-ceph-argparse");
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
if (! preg(pattern:"^(16\.04|18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'ceph', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'ceph-common', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'ceph-fs-common', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'ceph-fuse', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'ceph-mds', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'ceph-resource-agents', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'ceph-test', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'libcephfs-dev', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'libcephfs-java', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'libcephfs-jni', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'libcephfs1', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'librados-dev', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'librados2', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'libradosstriper-dev', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'libradosstriper1', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'librbd-dev', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'librbd1', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'librgw-dev', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'librgw2', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'python-ceph', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'python-cephfs', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'python-rados', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'python-rbd', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'radosgw', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'rbd-fuse', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'rbd-mirror', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'rbd-nbd', 'pkgver': '10.2.11-0ubuntu0.16.04.3'},
    {'osver': '18.04', 'pkgname': 'ceph', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'ceph-base', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'ceph-common', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'ceph-fuse', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'ceph-mds', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'ceph-mgr', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'ceph-mon', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'ceph-osd', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'ceph-resource-agents', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'ceph-test', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'libcephfs-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'libcephfs-java', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'libcephfs-jni', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'libcephfs2', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'librados-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'librados2', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'libradosstriper-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'libradosstriper1', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'librbd-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'librbd1', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'librgw-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'librgw2', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'python-ceph', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'python-cephfs', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'python-rados', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'python-rbd', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'python-rgw', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'python3-ceph-argparse', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'python3-cephfs', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'python3-rados', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'python3-rbd', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'python3-rgw', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'rados-objclass-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'radosgw', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'rbd-fuse', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'rbd-mirror', 'pkgver': '12.2.13-0ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'rbd-nbd', 'pkgver': '12.2.13-0ubuntu0.18.04.4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph / ceph-base / ceph-common / ceph-fs-common / ceph-fuse / ceph-mds / etc');
}