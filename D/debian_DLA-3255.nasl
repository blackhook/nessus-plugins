#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3255. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(169451);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/02");

  script_cve_id(
    "CVE-2022-38850",
    "CVE-2022-38851",
    "CVE-2022-38855",
    "CVE-2022-38858",
    "CVE-2022-38860",
    "CVE-2022-38861",
    "CVE-2022-38863",
    "CVE-2022-38864",
    "CVE-2022-38865",
    "CVE-2022-38866"
  );

  script_name(english:"Debian DLA-3255-1 : mplayer - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3255 advisory.

  - The MPlayer Project mencoder SVN-r38374-13.0.1 is vulnerable to Divide By Zero via the function config ()
    of llibmpcodecs/vf_scale.c. (CVE-2022-38850)

  - Certain The MPlayer Project products are vulnerable to Out-of-bounds Read via function read_meta_record()
    of mplayer/libmpdemux/asfheader.c. This affects mplayer SVN-r38374-13.0.1 and mencoder SVN-r38374-13.0.1.
    (CVE-2022-38851)

  - Certain The MPlayer Project products are vulnerable to Buffer Overflow via function gen_sh_video () of
    mplayer/libmpdemux/demux_mov.c. This affects mplayer SVN-r38374-13.0.1 and mencoder SVN-r38374-13.0.1.
    (CVE-2022-38855)

  - Certain The MPlayer Project products are vulnerable to Buffer Overflow via function mov_build_index() of
    libmpdemux/demux_mov.c. This affects mplayer SVN-r38374-13.0.1 and mencoder SVN-r38374-13.0.1.
    (CVE-2022-38858)

  - Certain The MPlayer Project products are vulnerable to Divide By Zero via function demux_open_avi() of
    libmpdemux/demux_avi.c which affects mencoder. This affects mplayer SVN-r38374-13.0.1 and mencoder
    SVN-r38374-13.0.1. (CVE-2022-38860)

  - The MPlayer Project mplayer SVN-r38374-13.0.1 is vulnerable to memory corruption via function
    free_mp_image() of libmpcodecs/mp_image.c. (CVE-2022-38861)

  - Certain The MPlayer Project products are vulnerable to Buffer Overflow via function mp_getbits() of
    libmpdemux/mpeg_hdr.c which affects mencoder and mplayer. This affects mecoder SVN-r38374-13.0.1 and
    mplayer SVN-r38374-13.0.1. (CVE-2022-38863)

  - Certain The MPlayer Project products are vulnerable to Buffer Overflow via the function mp_unescape03() of
    libmpdemux/mpeg_hdr.c. This affects mencoder SVN-r38374-13.0.1 and mplayer SVN-r38374-13.0.1.
    (CVE-2022-38864)

  - Certain The MPlayer Project products are vulnerable to Divide By Zero via the function
    demux_avi_read_packet of libmpdemux/demux_avi.c. This affects mplyer SVN-r38374-13.0.1 and mencoder
    SVN-r38374-13.0.1. (CVE-2022-38865)

  - Certain The MPlayer Project products are vulnerable to Buffer Overflow via read_avi_header() of
    libmpdemux/aviheader.c . This affects mplayer SVN-r38374-13.0.1 and mencoder SVN-r38374-13.0.1.
    (CVE-2022-38866)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/mplayer");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3255");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38850");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38851");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38855");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38858");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38860");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38861");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38863");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38864");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38865");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38866");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/mplayer");
  script_set_attribute(attribute:"solution", value:
"Upgrade the mplayer packages.

For Debian 10 buster, these problems have been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38866");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mencoder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mplayer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mplayer-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mplayer-gui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'mencoder', 'reference': '2:1.3.0-8+deb10u1'},
    {'release': '10.0', 'prefix': 'mplayer', 'reference': '2:1.3.0-8+deb10u1'},
    {'release': '10.0', 'prefix': 'mplayer-doc', 'reference': '2:1.3.0-8+deb10u1'},
    {'release': '10.0', 'prefix': 'mplayer-gui', 'reference': '2:1.3.0-8+deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mencoder / mplayer / mplayer-doc / mplayer-gui');
}
