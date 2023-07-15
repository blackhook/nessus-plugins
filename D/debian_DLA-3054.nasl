#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3054. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(162408);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/21");

  script_cve_id(
    "CVE-2017-13755",
    "CVE-2017-13756",
    "CVE-2017-13760",
    "CVE-2018-19497",
    "CVE-2019-1010065",
    "CVE-2020-10232"
  );

  script_name(english:"Debian DLA-3054-1 : sleuthkit - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3054 advisory.

  - In The Sleuth Kit (TSK) 4.4.2, opening a crafted ISO 9660 image triggers an out-of-bounds read in
    iso9660_proc_dir() in tsk/fs/iso9660_dent.c in libtskfs.a, as demonstrated by fls. (CVE-2017-13755)

  - In The Sleuth Kit (TSK) 4.4.2, opening a crafted disk image triggers infinite recursion in
    dos_load_ext_table() in tsk/vs/dos.c in libtskvs.a, as demonstrated by mmls. (CVE-2017-13756)

  - In The Sleuth Kit (TSK) 4.4.2, fls hangs on a corrupt exfat image in tsk_img_read() in tsk/img/img_io.c in
    libtskimg.a. (CVE-2017-13760)

  - In The Sleuth Kit (TSK) through 4.6.4, hfs_cat_traverse in tsk/fs/hfs.c does not properly determine when a
    key length is too large, which allows attackers to cause a denial of service (SEGV on unknown address with
    READ memory access in a tsk_getu16 call in hfs_dir_open_meta_cb in tsk/fs/hfs_dent.c). (CVE-2018-19497)

  - The Sleuth Kit 4.6.0 and earlier is affected by: Integer Overflow. The impact is: Opening crafted disk
    image triggers crash in tsk/fs/hfs_dent.c:237. The component is: Overflow in fls tool used on HFS image.
    Bug is in tsk/fs/hfs.c file in function hfs_cat_traverse() in lines: 952, 1062. The attack vector is:
    Victim must open a crafted HFS filesystem image. (CVE-2019-1010065)

  - In version 4.8.0 and earlier of The Sleuth Kit (TSK), there is a stack buffer overflow vulnerability in
    the YAFFS file timestamp parsing logic in yaffsfs_istat() in fs/yaffs.c. (CVE-2020-10232)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/sleuthkit");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3054");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-13755");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-13756");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-13760");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-19497");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-1010065");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-10232");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/sleuthkit");
  script_set_attribute(attribute:"solution", value:
"Upgrade the sleuthkit packages.

For Debian 9 stretch, these problems have been fixed in version 4.4.0-5+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10232");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtsk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtsk13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sleuthkit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'libtsk-dev', 'reference': '4.4.0-5+deb9u1'},
    {'release': '9.0', 'prefix': 'libtsk13', 'reference': '4.4.0-5+deb9u1'},
    {'release': '9.0', 'prefix': 'sleuthkit', 'reference': '4.4.0-5+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtsk-dev / libtsk13 / sleuthkit');
}
