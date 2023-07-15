#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2819. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155439);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/17");

  script_cve_id(
    "CVE-2021-33285",
    "CVE-2021-33286",
    "CVE-2021-33287",
    "CVE-2021-33289",
    "CVE-2021-35266",
    "CVE-2021-35267",
    "CVE-2021-35268",
    "CVE-2021-35269",
    "CVE-2021-39251",
    "CVE-2021-39252",
    "CVE-2021-39253",
    "CVE-2021-39254",
    "CVE-2021-39255",
    "CVE-2021-39256",
    "CVE-2021-39257",
    "CVE-2021-39258",
    "CVE-2021-39259",
    "CVE-2021-39260",
    "CVE-2021-39261",
    "CVE-2021-39262",
    "CVE-2021-39263"
  );

  script_name(english:"Debian DLA-2819-1 : ntfs-3g - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2819 advisory.

  - In NTFS-3G versions < 2021.8.22, when a specially crafted NTFS attribute is supplied to the function
    ntfs_get_attribute_value, a heap buffer overflow can occur allowing for memory disclosure or denial of
    service. The vulnerability is caused by an out-of-bound buffer access which can be triggered by mounting a
    crafted ntfs partition. The root cause is a missing consistency check after reading an MFT record : the
    bytes_in_use field should be less than the bytes_allocated field. When it is not, the parsing of the
    records proceeds into the wild. (CVE-2021-33285)

  - In NTFS-3G versions < 2021.8.22, when a specially crafted unicode string is supplied in an NTFS image a
    heap buffer overflow can occur and allow for code execution. (CVE-2021-33286)

  - In NTFS-3G versions < 2021.8.22, when specially crafted NTFS attributes are read in the function
    ntfs_attr_pread_i, a heap buffer overflow can occur and allow for writing to arbitrary memory or denial of
    service of the application. (CVE-2021-33287)

  - In NTFS-3G versions < 2021.8.22, when a specially crafted MFT section is supplied in an NTFS image a heap
    buffer overflow can occur and allow for code execution. (CVE-2021-33289)

  - In NTFS-3G versions < 2021.8.22, when a specially crafted NTFS inode pathname is supplied in an NTFS image
    a heap buffer overflow can occur resulting in memory disclosure, denial of service and even code
    execution. (CVE-2021-35266)

  - NTFS-3G versions < 2021.8.22, a stack buffer overflow can occur when correcting differences in the MFT and
    MFTMirror allowing for code execution or escalation of privileges when setuid-root. (CVE-2021-35267)

  - In NTFS-3G versions < 2021.8.22, when a specially crafted NTFS inode is loaded in the function
    ntfs_inode_real_open, a heap buffer overflow can occur allowing for code execution and escalation of
    privileges. (CVE-2021-35268)

  - NTFS-3G versions < 2021.8.22, when a specially crafted NTFS attribute from the MFT is setup in the
    function ntfs_attr_setup_flag, a heap buffer overflow can occur allowing for code execution and escalation
    of privileges. (CVE-2021-35269)

  - A crafted NTFS image can cause a NULL pointer dereference in ntfs_extent_inode_open in NTFS-3G <
    2021.8.22. (CVE-2021-39251)

  - A crafted NTFS image can cause an out-of-bounds read in ntfs_ie_lookup in NTFS-3G < 2021.8.22.
    (CVE-2021-39252)

  - A crafted NTFS image can cause an out-of-bounds read in ntfs_runlists_merge_i in NTFS-3G < 2021.8.22.
    (CVE-2021-39253)

  - A crafted NTFS image can cause an integer overflow in memmove, leading to a heap-based buffer overflow in
    the function ntfs_attr_record_resize, in NTFS-3G < 2021.8.22. (CVE-2021-39254)

  - A crafted NTFS image can trigger an out-of-bounds read, caused by an invalid attribute in
    ntfs_attr_find_in_attrdef, in NTFS-3G < 2021.8.22. (CVE-2021-39255)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_inode_lookup_by_name in NTFS-3G <
    2021.8.22. (CVE-2021-39256)

  - A crafted NTFS image with an unallocated bitmap can lead to a endless recursive function call chain
    (starting from ntfs_attr_pwrite), causing stack consumption in NTFS-3G < 2021.8.22. (CVE-2021-39257)

  - A crafted NTFS image can cause out-of-bounds reads in ntfs_attr_find and ntfs_external_attr_find in
    NTFS-3G < 2021.8.22. (CVE-2021-39258)

  - A crafted NTFS image can trigger an out-of-bounds access, caused by an unsanitized attribute length in
    ntfs_inode_lookup_by_name, in NTFS-3G < 2021.8.22. (CVE-2021-39259)

  - A crafted NTFS image can cause an out-of-bounds access in ntfs_inode_sync_standard_information in NTFS-3G
    < 2021.8.22. (CVE-2021-39260)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_compressed_pwrite in NTFS-3G <
    2021.8.22. (CVE-2021-39261)

  - A crafted NTFS image can cause an out-of-bounds access in ntfs_decompress in NTFS-3G < 2021.8.22.
    (CVE-2021-39262)

  - A crafted NTFS image can trigger a heap-based buffer overflow, caused by an unsanitized attribute in
    ntfs_get_attribute_value, in NTFS-3G < 2021.8.22. (CVE-2021-39263)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=988386");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ntfs-3g");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2819");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33285");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33286");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33287");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33289");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-35266");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-35267");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-35268");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-35269");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39251");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39252");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39253");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39254");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39255");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39256");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39257");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39258");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39259");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39260");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39261");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39262");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39263");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/ntfs-3g");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ntfs-3g packages.

For Debian 9 stretch, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39263");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libntfs-3g871");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntfs-3g");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntfs-3g-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntfs-3g-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'libntfs-3g871', 'reference': '1:2016.2.22AR.1+dfsg-1+deb9u2'},
    {'release': '9.0', 'prefix': 'ntfs-3g', 'reference': '1:2016.2.22AR.1+dfsg-1+deb9u2'},
    {'release': '9.0', 'prefix': 'ntfs-3g-dbg', 'reference': '1:2016.2.22AR.1+dfsg-1+deb9u2'},
    {'release': '9.0', 'prefix': 'ntfs-3g-dev', 'reference': '1:2016.2.22AR.1+dfsg-1+deb9u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libntfs-3g871 / ntfs-3g / ntfs-3g-dbg / ntfs-3g-dev');
}
