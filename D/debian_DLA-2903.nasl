#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2903. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158247);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2017-14608",
    "CVE-2017-16909",
    "CVE-2017-16910",
    "CVE-2018-5800",
    "CVE-2018-5801",
    "CVE-2018-5802",
    "CVE-2018-5804",
    "CVE-2018-5805",
    "CVE-2018-5806",
    "CVE-2018-5807",
    "CVE-2018-5808",
    "CVE-2018-5810",
    "CVE-2018-5811",
    "CVE-2018-5812",
    "CVE-2018-5813",
    "CVE-2018-5815",
    "CVE-2018-5817",
    "CVE-2018-5818",
    "CVE-2018-5819",
    "CVE-2018-20363",
    "CVE-2018-20364",
    "CVE-2018-20365"
  );

  script_name(english:"Debian DLA-2903-1 : libraw - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2903 advisory.

  - In LibRaw through 0.18.4, an out of bounds read flaw related to kodak_65000_load_raw has been reported in
    dcraw/dcraw.c and internal/dcraw_common.cpp. An attacker could possibly exploit this flaw to disclose
    potentially sensitive memory or cause an application crash. (CVE-2017-14608)

  - An error related to the LibRaw::panasonic_load_raw() function (dcraw_common.cpp) in LibRaw versions
    prior to 0.18.6 can be exploited to cause a heap-based buffer overflow and subsequently cause a crash via
    a specially crafted TIFF image. (CVE-2017-16909)

  - An error within the LibRaw::xtrans_interpolate() function (internal/dcraw_common.cpp) in LibRaw versions
    prior to 0.18.6 can be exploited to cause an invalid read memory access and subsequently a Denial of
    Service condition. (CVE-2017-16910)

  - LibRaw::raw2image in libraw_cxx.cpp in LibRaw 0.19.1 has a NULL pointer dereference. (CVE-2018-20363)

  - LibRaw::copy_bayer in libraw_cxx.cpp in LibRaw 0.19.1 has a NULL pointer dereference. (CVE-2018-20364)

  - LibRaw::raw2image() in libraw_cxx.cpp has a heap-based buffer overflow. (CVE-2018-20365)

  - An off-by-one error within the LibRaw::kodak_ycbcr_load_raw() function (internal/dcraw_common.cpp) in
    LibRaw versions prior to 0.18.7 can be exploited to cause a heap-based buffer overflow and subsequently
    cause a crash. (CVE-2018-5800)

  - An error within the LibRaw::unpack() function (src/libraw_cxx.cpp) in LibRaw versions prior to 0.18.7
    can be exploited to trigger a NULL pointer dereference. (CVE-2018-5801)

  - An error within the kodak_radc_load_raw() function (internal/dcraw_common.cpp) related to the buf
    variable in LibRaw versions prior to 0.18.7 can be exploited to cause an out-of-bounds read memory access
    and subsequently cause a crash. (CVE-2018-5802)

  - A type confusion error within the identify() function (internal/dcraw_common.cpp) in LibRaw versions
    prior to 0.18.8 can be exploited to trigger a division by zero. (CVE-2018-5804)

  - A boundary error within the quicktake_100_load_raw() function (internal/dcraw_common.cpp) in LibRaw
    versions prior to 0.18.8 can be exploited to cause a stack-based buffer overflow and subsequently cause a
    crash. (CVE-2018-5805)

  - An error within the leaf_hdr_load_raw() function (internal/dcraw_common.cpp) in LibRaw versions prior to
    0.18.8 can be exploited to trigger a NULL pointer dereference. (CVE-2018-5806)

  - An error within the samsung_load_raw() function (internal/dcraw_common.cpp) in LibRaw versions prior to
    0.18.9 can be exploited to cause an out-of-bounds read memory access and subsequently cause a crash.
    (CVE-2018-5807)

  - An error within the find_green() function (internal/dcraw_common.cpp) in LibRaw versions prior to 0.18.9
    can be exploited to cause a stack-based buffer overflow and subsequently execute arbitrary code.
    (CVE-2018-5808)

  - An error within the rollei_load_raw() function (internal/dcraw_common.cpp) in LibRaw versions prior to
    0.18.9 can be exploited to cause a heap-based buffer overflow and subsequently cause a crash.
    (CVE-2018-5810)

  - An error within the nikon_coolscan_load_raw() function (internal/dcraw_common.cpp) in LibRaw versions
    prior to 0.18.9 can be exploited to cause an out-of-bounds read memory access and subsequently cause a
    crash. (CVE-2018-5811)

  - An error within the nikon_coolscan_load_raw() function (internal/dcraw_common.cpp) in LibRaw versions
    prior to 0.18.9 can be exploited to trigger a NULL pointer dereference. (CVE-2018-5812)

  - An error within the parse_minolta() function (dcraw/dcraw.c) in LibRaw versions prior to 0.18.11 can be
    exploited to trigger an infinite loop via a specially crafted file. (CVE-2018-5813)

  - An integer overflow error within the parse_qt() function (internal/dcraw_common.cpp) in LibRaw versions
    prior to 0.18.12 can be exploited to trigger an infinite loop via a specially crafted Apple QuickTime
    file. (CVE-2018-5815)

  - A type confusion error within the unpacked_load_raw() function within LibRaw versions prior to 0.19.1
    (internal/dcraw_common.cpp) can be exploited to trigger an infinite loop. (CVE-2018-5817)

  - An error within the parse_rollei() function (internal/dcraw_common.cpp) within LibRaw versions prior to
    0.19.1 can be exploited to trigger an infinite loop. (CVE-2018-5818)

  - An error within the parse_sinar_ia() function (internal/dcraw_common.cpp) within LibRaw versions prior
    to 0.19.1 can be exploited to exhaust available CPU resources. (CVE-2018-5819)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libraw");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2903");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-14608");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-16909");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-16910");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-20363");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-20364");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-20365");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5800");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5801");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5802");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5804");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5805");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5806");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5807");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5808");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5810");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5811");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5812");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5813");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5815");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5817");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5818");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5819");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/libraw");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libraw packages.

For Debian 9 stretch, these problems have been fixed in version 0.17.2-6+deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5810");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-14608");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libraw-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libraw-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libraw-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libraw15");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'libraw-bin', 'reference': '0.17.2-6+deb9u2'},
    {'release': '9.0', 'prefix': 'libraw-dev', 'reference': '0.17.2-6+deb9u2'},
    {'release': '9.0', 'prefix': 'libraw-doc', 'reference': '0.17.2-6+deb9u2'},
    {'release': '9.0', 'prefix': 'libraw15', 'reference': '0.17.2-6+deb9u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libraw-bin / libraw-dev / libraw-doc / libraw15');
}
