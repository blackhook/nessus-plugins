#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2735. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152519);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/12");

  script_cve_id(
    "CVE-2018-14662",
    "CVE-2018-16846",
    "CVE-2020-1760",
    "CVE-2020-10753",
    "CVE-2021-3524"
  );

  script_name(english:"Debian DLA-2735-1 : ceph - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2735 advisory.

  - It was found Ceph versions before 13.2.4 that authenticated ceph users with read only permissions could
    steal dm-crypt encryption keys used in ceph disk encryption. (CVE-2018-14662)

  - It was found in Ceph versions before 13.2.4 that authenticated ceph RGW users can cause a denial of
    service against OMAPs holding bucket indices. (CVE-2018-16846)

  - A flaw was found in the Red Hat Ceph Storage RadosGW (Ceph Object Gateway). The vulnerability is related
    to the injection of HTTP headers via a CORS ExposeHeader tag. The newline character in the ExposeHeader
    tag in the CORS configuration file generates a header injection in the response when the CORS request is
    made. Ceph versions 3.x and 4.x are vulnerable to this issue. (CVE-2020-10753)

  - A flaw was found in the Ceph Object Gateway, where it supports request sent by an anonymous user in Amazon
    S3. This flaw could lead to potential XSS attacks due to the lack of proper neutralization of untrusted
    input. (CVE-2020-1760)

  - A flaw was found in the Red Hat Ceph Storage RadosGW (Ceph Object Gateway) in versions before 14.2.21. The
    vulnerability is related to the injection of HTTP headers via a CORS ExposeHeader tag. The newline
    character in the ExposeHeader tag in the CORS configuration file generates a header injection in the
    response when the CORS request is made. In addition, the prior bug fix for CVE-2020-10753 did not account
    for the use of \r as a header separator, thus a new flaw has been created. (CVE-2021-3524)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=921948");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ceph");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2735");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-14662");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-16846");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-10753");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1760");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3524");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/ceph");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ceph packages.

For Debian 9 stretch, these problems have been fixed in version 10.2.11-2+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3524");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-fs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librados-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libradosstriper-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librbd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librgw-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rbd-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rbd-nbd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'ceph', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'ceph-base', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'ceph-common', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'ceph-fs-common', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'ceph-fuse', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'ceph-mds', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'ceph-mon', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'ceph-osd', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'ceph-resource-agents', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'ceph-test', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libcephfs-dev', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libcephfs-java', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libcephfs-jni', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libcephfs1', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'librados-dev', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'librados2', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libradosstriper-dev', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libradosstriper1', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'librbd-dev', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'librbd1', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'librgw-dev', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'librgw2', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-ceph', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-cephfs', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-rados', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-rbd', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'radosgw', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'rbd-fuse', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'rbd-mirror', 'reference': '10.2.11-2+deb9u1'},
    {'release': '9.0', 'prefix': 'rbd-nbd', 'reference': '10.2.11-2+deb9u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph / ceph-base / ceph-common / ceph-fs-common / ceph-fuse / ceph-mds / etc');
}
