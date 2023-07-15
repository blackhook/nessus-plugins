#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2806. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154881);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2018-1088",
    "CVE-2018-10841",
    "CVE-2018-10904",
    "CVE-2018-10907",
    "CVE-2018-10911",
    "CVE-2018-10913",
    "CVE-2018-10914",
    "CVE-2018-10923",
    "CVE-2018-10926",
    "CVE-2018-10927",
    "CVE-2018-10928",
    "CVE-2018-10929",
    "CVE-2018-10930",
    "CVE-2018-14652",
    "CVE-2018-14653",
    "CVE-2018-14654",
    "CVE-2018-14659",
    "CVE-2018-14660",
    "CVE-2018-14661"
  );

  script_name(english:"Debian DLA-2806-1 : glusterfs - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2806 advisory.

  - glusterfs is vulnerable to privilege escalation on gluster server nodes. An authenticated gluster client
    via TLS could use gluster cli with --remote-host command to add it self to trusted storage pool and
    perform privileged gluster operations like adding other machines to trusted storage pool, start, stop, and
    delete volumes. (CVE-2018-10841)

  - A privilege escalation flaw was found in gluster 3.x snapshot scheduler. Any gluster client allowed to
    mount gluster volumes could also mount shared gluster storage volume and escalate privileges by scheduling
    malicious cronjob via symlink. (CVE-2018-1088)

  - It was found that glusterfs server does not properly sanitize file paths in the trusted.io-stats-dump
    extended attribute which is used by the debug/io-stats translator. Attacker can use this flaw to create
    files and execute arbitrary code. To exploit this attacker would require sufficient access to modify the
    extended attributes of files on a gluster volume. (CVE-2018-10904)

  - It was found that glusterfs server is vulnerable to multiple stack based buffer overflows due to functions
    in server-rpc-fopc.c allocating fixed size buffers using 'alloca(3)'. An authenticated attacker could
    exploit this by mounting a gluster volume and sending a string longer that the fixed buffer size to cause
    crash or potential code execution. (CVE-2018-10907)

  - A flaw was found in the way dic_unserialize function of glusterfs does not handle negative key length
    values. An attacker could use this flaw to read memory from other locations into the stored dict value.
    (CVE-2018-10911)

  - An information disclosure vulnerability was discovered in glusterfs server. An attacker could issue a
    xattr request via glusterfs FUSE to determine the existence of any file. (CVE-2018-10913)

  - It was found that an attacker could issue a xattr request via glusterfs FUSE to cause gluster brick
    process to crash which will result in a remote denial of service. If gluster multiplexing is enabled this
    will result in a crash of multiple bricks and gluster volumes. (CVE-2018-10914)

  - It was found that the mknod call derived from mknod(2) can create files pointing to devices on a
    glusterfs server node. An authenticated attacker could use this to create an arbitrary device and read
    data from any device attached to the glusterfs server node. (CVE-2018-10923)

  - A flaw was found in RPC request using gfs3_mknod_req supported by glusterfs server. An authenticated
    attacker could use this flaw to write files to an arbitrary location via path traversal and execute
    arbitrary code on a glusterfs server node. (CVE-2018-10926)

  - A flaw was found in RPC request using gfs3_lookup_req in glusterfs server. An authenticated attacker could
    use this flaw to leak information and execute remote denial of service by crashing gluster brick process.
    (CVE-2018-10927)

  - A flaw was found in RPC request using gfs3_symlink_req in glusterfs server which allows symlink
    destinations to point to file paths outside of the gluster volume. An authenticated attacker could use
    this flaw to create arbitrary symlinks pointing anywhere on the server and execute arbitrary code on
    glusterfs server nodes. (CVE-2018-10928)

  - A flaw was found in RPC request using gfs2_create_req in glusterfs server. An authenticated attacker could
    use this flaw to create arbitrary files and execute arbitrary code on glusterfs server nodes.
    (CVE-2018-10929)

  - A flaw was found in RPC request using gfs3_rename_req in glusterfs server. An authenticated attacker could
    use this flaw to write to a destination outside the gluster volume. (CVE-2018-10930)

  - The Gluster file system through versions 3.12 and 4.1.4 is vulnerable to a buffer overflow in the
    'features/index' translator via the code handling the 'GF_XATTR_CLRLK_CMD' xattr in the 'pl_getxattr'
    function. A remote authenticated attacker could exploit this on a mounted volume to cause a denial of
    service. (CVE-2018-14652)

  - The Gluster file system through versions 4.1.4 and 3.12 is vulnerable to a heap-based buffer overflow in
    the '__server_getspec' function via the 'gf_getspec_req' RPC message. A remote authenticated attacker
    could exploit this to cause a denial of service or other potential unspecified impact. (CVE-2018-14653)

  - The Gluster file system through version 4.1.4 is vulnerable to abuse of the 'features/index' translator. A
    remote attacker with access to mount volumes could exploit this via the 'GF_XATTROP_ENTRY_IN_KEY' xattrop
    to create arbitrary, empty files on the target server. (CVE-2018-14654)

  - The Gluster file system through versions 4.1.4 and 3.1.2 is vulnerable to a denial of service attack via
    use of the 'GF_XATTR_IOSTATS_DUMP_KEY' xattr. A remote, authenticated attacker could exploit this by
    mounting a Gluster volume and repeatedly calling 'setxattr(2)' to trigger a state dump and create an
    arbitrary number of files in the server's runtime directory. (CVE-2018-14659)

  - A flaw was found in glusterfs server through versions 4.1.4 and 3.1.2 which allowed repeated usage of
    GF_META_LOCK_KEY xattr. A remote, authenticated attacker could use this flaw to create multiple locks for
    single inode by using setxattr repetitively resulting in memory exhaustion of glusterfs server node.
    (CVE-2018-14660)

  - It was found that usage of snprintf function in feature/locks translator of glusterfs server 3.8.4, as
    shipped with Red Hat Gluster Storage, was vulnerable to a format string attack. A remote, authenticated
    attacker could use this flaw to cause remote denial of service. (CVE-2018-14661)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=909215");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/glusterfs");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2806");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10841");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-1088");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10904");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10907");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10911");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10913");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10914");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10923");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10926");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10927");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10928");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10929");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10930");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-14652");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-14653");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-14654");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-14659");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-14660");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-14661");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/glusterfs");
  script_set_attribute(attribute:"solution", value:
"Upgrade the glusterfs packages.

For Debian 9 stretch, these problems have been fixed in version 3.8.8-1+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14654");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-14653");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glusterfs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glusterfs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glusterfs-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glusterfs-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'glusterfs-client', 'reference': '3.8.8-1+deb9u1'},
    {'release': '9.0', 'prefix': 'glusterfs-common', 'reference': '3.8.8-1+deb9u1'},
    {'release': '9.0', 'prefix': 'glusterfs-dbg', 'reference': '3.8.8-1+deb9u1'},
    {'release': '9.0', 'prefix': 'glusterfs-server', 'reference': '3.8.8-1+deb9u1'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glusterfs-client / glusterfs-common / glusterfs-dbg / glusterfs-server');
}
