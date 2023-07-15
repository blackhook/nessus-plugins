##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4706-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145517);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-10736", "CVE-2020-10753", "CVE-2020-25660");
  script_xref(name:"USN", value:"4706-1");

  script_name(english:"Ubuntu 20.04 LTS / 20.10 : Ceph vulnerabilities (USN-4706-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 20.10 host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4706-1 advisory.

  - An authorization bypass vulnerability was found in Ceph versions 15.2.0 before 15.2.2, where the ceph-mon
    and ceph-mgr daemons do not properly restrict access, resulting in gaining access to unauthorized
    resources. This flaw allows an authenticated client to modify the configuration and possibly conduct
    further attacks. (CVE-2020-10736)

  - A flaw was found in the Red Hat Ceph Storage RadosGW (Ceph Object Gateway). The vulnerability is related
    to the injection of HTTP headers via a CORS ExposeHeader tag. The newline character in the ExposeHeader
    tag in the CORS configuration file generates a header injection in the response when the CORS request is
    made. Ceph versions 3.x and 4.x are vulnerable to this issue. (CVE-2020-10753)

  - A flaw was found in the Cephx authentication protocol in versions before 15.2.6 and before 14.2.14, where
    it does not verify Ceph clients correctly and is then vulnerable to replay attacks in Nautilus. This flaw
    allows an attacker with access to the Ceph cluster network to authenticate with the Ceph service via a
    packet sniffer and perform actions allowed by the Ceph service. This issue is a reintroduction of
    CVE-2018-1128, affecting the msgr2 protocol. The msgr 2 protocol is used for all communication except
    older clients that do not support the msgr2 protocol. The msgr1 protocol is not affected. The highest
    threat from this vulnerability is to confidentiality, integrity, and system availability. (CVE-2020-25660)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4706-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
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
if (! preg(pattern:"^(20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '20.04', 'pkgname': 'ceph', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'ceph-base', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'ceph-common', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'ceph-fuse', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'ceph-immutable-object-cache', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'ceph-mds', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-cephadm', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-dashboard', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-diskprediction-cloud', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-diskprediction-local', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-k8sevents', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-modules-core', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-rook', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'ceph-mon', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'ceph-osd', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'ceph-resource-agents', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'cephadm', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'cephfs-shell', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libcephfs-dev', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libcephfs-java', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libcephfs-jni', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libcephfs2', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'librados-dev', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'librados2', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libradospp-dev', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libradosstriper-dev', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libradosstriper1', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'librbd-dev', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'librbd1', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'librgw-dev', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'librgw2', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'python3-ceph', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'python3-ceph-argparse', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'python3-ceph-common', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'python3-cephfs', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'python3-rados', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'python3-rbd', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'python3-rgw', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'rados-objclass-dev', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'radosgw', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'rbd-fuse', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'rbd-mirror', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'rbd-nbd', 'pkgver': '15.2.7-0ubuntu0.20.04.2'},
    {'osver': '20.10', 'pkgname': 'ceph', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'ceph-base', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'ceph-common', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'ceph-fuse', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'ceph-immutable-object-cache', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'ceph-mds', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'ceph-mgr', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'ceph-mgr-cephadm', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'ceph-mgr-dashboard', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'ceph-mgr-diskprediction-cloud', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'ceph-mgr-diskprediction-local', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'ceph-mgr-k8sevents', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'ceph-mgr-modules-core', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'ceph-mgr-rook', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'ceph-mon', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'ceph-osd', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'ceph-resource-agents', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'cephadm', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'cephfs-shell', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'libcephfs-dev', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'libcephfs-java', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'libcephfs-jni', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'libcephfs2', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'librados-dev', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'librados2', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'libradospp-dev', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'libradosstriper-dev', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'libradosstriper1', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'librbd-dev', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'librbd1', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'librgw-dev', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'librgw2', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'python3-ceph', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'python3-ceph-argparse', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'python3-ceph-common', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'python3-cephfs', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'python3-rados', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'python3-rbd', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'python3-rgw', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'rados-objclass-dev', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'radosgw', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'rbd-fuse', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'rbd-mirror', 'pkgver': '15.2.7-0ubuntu0.20.10.3'},
    {'osver': '20.10', 'pkgname': 'rbd-nbd', 'pkgver': '15.2.7-0ubuntu0.20.10.3'}
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