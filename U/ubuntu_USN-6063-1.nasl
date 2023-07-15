#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6063-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175537);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/13");

  script_cve_id(
    "CVE-2021-3979",
    "CVE-2022-0670",
    "CVE-2022-3650",
    "CVE-2022-3854"
  );
  script_xref(name:"USN", value:"6063-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : Ceph vulnerabilities (USN-6063-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6063-1 advisory.

  - A key length flaw was found in Red Hat Ceph Storage. An attacker can exploit the fact that the key length
    is incorrectly passed in an encryption algorithm to create a non random key, which is weaker and can be
    exploited for loss of confidentiality and integrity on encrypted disks. (CVE-2021-3979)

  - A flaw was found in Openstack manilla owning a Ceph File system share, which enables the owner to
    read/write any manilla share or entire file system. The vulnerability is due to a bug in the volumes
    plugin in Ceph Manager. This allows an attacker to compromise Confidentiality and Integrity of a file
    system. Fixed in RHCS 5.2 and Ceph 17.2.2. (CVE-2022-0670)

  - A privilege escalation flaw was found in Ceph. Ceph-crash.service allows a local attacker to escalate
    privileges to root in the form of a crash dump, and dump privileged information. (CVE-2022-3650)

  - A flaw was found in Ceph, relating to the URL processing on RGW backends. An attacker can exploit the URL
    processing by providing a null URL to crash the RGW, causing a denial of service. (CVE-2022-3854)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6063-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0670");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-grafana-dashboards");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-prometheus-alerts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-volume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cephfs-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:crimson-osd");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsqlite3-mod-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsqlite3-mod-ceph-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-rgw");
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
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(18\.04|20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'ceph', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'ceph-base', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'ceph-common', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'ceph-fuse', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'ceph-mds', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'ceph-mgr', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'ceph-mon', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'ceph-osd', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'ceph-resource-agents', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'ceph-test', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'libcephfs-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'libcephfs-java', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'libcephfs-jni', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'libcephfs2', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'librados-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'librados2', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'libradosstriper-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'libradosstriper1', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'librbd-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'librbd1', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'librgw-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'librgw2', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'python-ceph', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'python-cephfs', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'python-rados', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'python-rbd', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'python-rgw', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'python3-ceph-argparse', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'python3-cephfs', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'python3-rados', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'python3-rbd', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'python3-rgw', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'rados-objclass-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'radosgw', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'rbd-fuse', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'rbd-mirror', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'rbd-nbd', 'pkgver': '12.2.13-0ubuntu0.18.04.11'},
    {'osver': '20.04', 'pkgname': 'ceph', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'ceph-base', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'ceph-common', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'ceph-fuse', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'ceph-immutable-object-cache', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'ceph-mds', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-cephadm', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-dashboard', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-diskprediction-cloud', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-diskprediction-local', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-k8sevents', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-modules-core', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-rook', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'ceph-mon', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'ceph-osd', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'ceph-resource-agents', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'cephadm', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'cephfs-shell', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libcephfs-dev', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libcephfs-java', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libcephfs-jni', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libcephfs2', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'librados-dev', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'librados2', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libradospp-dev', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libradosstriper-dev', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libradosstriper1', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'librbd-dev', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'librbd1', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'librgw-dev', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'librgw2', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'python3-ceph', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'python3-ceph-argparse', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'python3-ceph-common', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'python3-cephfs', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'python3-rados', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'python3-rbd', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'python3-rgw', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'rados-objclass-dev', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'radosgw', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'rbd-fuse', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'rbd-mirror', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'rbd-nbd', 'pkgver': '15.2.17-0ubuntu0.20.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-base', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-common', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-fuse', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-grafana-dashboards', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-immutable-object-cache', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-mds', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-mgr', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-mgr-cephadm', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-mgr-dashboard', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-mgr-diskprediction-local', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-mgr-k8sevents', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-mgr-modules-core', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-mgr-rook', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-mon', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-osd', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-prometheus-alerts', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-resource-agents', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'ceph-volume', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'cephadm', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'cephfs-shell', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'crimson-osd', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libcephfs-dev', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libcephfs-java', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libcephfs-jni', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libcephfs2', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'librados-dev', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'librados2', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libradospp-dev', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libradosstriper-dev', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libradosstriper1', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'librbd-dev', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'librbd1', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'librgw-dev', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'librgw2', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libsqlite3-mod-ceph', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libsqlite3-mod-ceph-dev', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'python3-ceph', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'python3-ceph-argparse', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'python3-ceph-common', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'python3-cephfs', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'python3-rados', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'python3-rbd', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'python3-rgw', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'rados-objclass-dev', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'radosgw', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'rbd-fuse', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'rbd-mirror', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'rbd-nbd', 'pkgver': '17.2.5-0ubuntu0.22.04.3'},
    {'osver': '22.10', 'pkgname': 'ceph', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-base', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-common', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-fuse', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-grafana-dashboards', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-immutable-object-cache', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-mds', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-mgr', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-mgr-cephadm', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-mgr-dashboard', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-mgr-diskprediction-local', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-mgr-k8sevents', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-mgr-modules-core', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-mgr-rook', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-mon', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-osd', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-prometheus-alerts', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-resource-agents', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'ceph-volume', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'cephadm', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'cephfs-shell', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'crimson-osd', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'libcephfs-dev', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'libcephfs-java', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'libcephfs-jni', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'libcephfs2', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'librados-dev', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'librados2', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'libradospp-dev', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'libradosstriper-dev', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'libradosstriper1', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'librbd-dev', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'librbd1', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'librgw-dev', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'librgw2', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'libsqlite3-mod-ceph', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'libsqlite3-mod-ceph-dev', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'python3-ceph', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'python3-ceph-argparse', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'python3-ceph-common', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'python3-cephfs', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'python3-rados', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'python3-rbd', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'python3-rgw', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'rados-objclass-dev', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'radosgw', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'rbd-fuse', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'rbd-mirror', 'pkgver': '17.2.5-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'rbd-nbd', 'pkgver': '17.2.5-0ubuntu0.22.10.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph / ceph-base / ceph-common / ceph-fuse / ceph-grafana-dashboards / etc');
}
