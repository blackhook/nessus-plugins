#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5160. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(162126);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2021-46790",
    "CVE-2022-30783",
    "CVE-2022-30784",
    "CVE-2022-30785",
    "CVE-2022-30786",
    "CVE-2022-30787",
    "CVE-2022-30788",
    "CVE-2022-30789"
  );

  script_name(english:"Debian DSA-5160-1 : ntfs-3g - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5160 advisory.

  - ntfsck in NTFS-3G through 2021.8.22 has a heap-based buffer overflow involving buffer+512*3-2. NOTE: the
    upstream position is that ntfsck is deprecated; however, it is shipped by some Linux distributions.
    (CVE-2021-46790)

  - An invalid return code in fuse_kern_mount enables intercepting of libfuse-lite protocol traffic between
    NTFS-3G and the kernel in NTFS-3G through 2021.8.22 when using libfuse-lite. (CVE-2022-30783)

  - A crafted NTFS image can cause heap exhaustion in ntfs_get_attribute_value in NTFS-3G through 2021.8.22.
    (CVE-2022-30784)

  - A file handle created in fuse_lib_opendir, and later used in fuse_lib_readdir, enables arbitrary memory
    read and write operations in NTFS-3G through 2021.8.22 when using libfuse-lite. (CVE-2022-30785)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_names_full_collate in NTFS-3G through
    2021.8.22. (CVE-2022-30786)

  - An integer underflow in fuse_lib_readdir enables arbitrary memory read operations in NTFS-3G through
    2021.8.22 when using libfuse-lite. (CVE-2022-30787)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_mft_rec_alloc in NTFS-3G through
    2021.8.22. (CVE-2022-30788)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_check_log_client_array in NTFS-3G
    through 2021.8.22. (CVE-2022-30789)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1011770");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ntfs-3g");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5160");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46790");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30783");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30784");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30785");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30786");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30787");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30788");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30789");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/ntfs-3g");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/ntfs-3g");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ntfs-3g packages.

For the stable distribution (bullseye), these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30785");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-46790");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libntfs-3g883");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntfs-3g");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntfs-3g-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntfs-3g-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libntfs-3g883', 'reference': '1:2017.3.23AR.3-3+deb10u2'},
    {'release': '10.0', 'prefix': 'ntfs-3g', 'reference': '1:2017.3.23AR.3-3+deb10u2'},
    {'release': '10.0', 'prefix': 'ntfs-3g-dev', 'reference': '1:2017.3.23AR.3-3+deb10u2'},
    {'release': '10.0', 'prefix': 'ntfs-3g-udeb', 'reference': '1:2017.3.23AR.3-3+deb10u2'},
    {'release': '11.0', 'prefix': 'libntfs-3g883', 'reference': '1:2017.3.23AR.3-4+deb11u2'},
    {'release': '11.0', 'prefix': 'ntfs-3g', 'reference': '1:2017.3.23AR.3-4+deb11u2'},
    {'release': '11.0', 'prefix': 'ntfs-3g-dev', 'reference': '1:2017.3.23AR.3-4+deb11u2'},
    {'release': '11.0', 'prefix': 'ntfs-3g-udeb', 'reference': '1:2017.3.23AR.3-4+deb11u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libntfs-3g883 / ntfs-3g / ntfs-3g-dev / ntfs-3g-udeb');
}
