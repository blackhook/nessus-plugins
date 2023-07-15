#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6180-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177459);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/20");

  script_cve_id(
    "CVE-2019-19721",
    "CVE-2020-13428",
    "CVE-2021-25801",
    "CVE-2021-25802",
    "CVE-2021-25803",
    "CVE-2021-25804",
    "CVE-2022-41325"
  );
  script_xref(name:"USN", value:"6180-1");
  script_xref(name:"IAVB", value:"2020-B-0025-S");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM / 22.10 : VLC media player vulnerabilities (USN-6180-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM / 22.10 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-6180-1 advisory.

  - An off-by-one error in the DecodeBlock function in codec/sdl_image.c in VideoLAN VLC media player before
    3.0.9 allows remote attackers to cause a denial of service (memory corruption) via a crafted image file.
    NOTE: this may be related to the SDL_Image product. (CVE-2019-19721)

  - A heap-based buffer overflow in the hxxx_AnnexB_to_xVC function in modules/packetizer/hxxx_nal.c in
    VideoLAN VLC media player before 3.0.11 for macOS/iOS allows remote attackers to cause a denial of service
    (application crash) or execute arbitrary code via a crafted H.264 Annex-B video (.avi for example) file.
    (CVE-2020-13428)

  - A buffer overflow vulnerability in the __Parse_indx component of VideoLAN VLC Media Player 3.0.11 allows
    attackers to cause an out-of-bounds read via a crafted .avi file. (CVE-2021-25801)

  - A buffer overflow vulnerability in the AVI_ExtractSubtitle component of VideoLAN VLC Media Player 3.0.11
    allows attackers to cause an out-of-bounds read via a crafted .avi file. (CVE-2021-25802)

  - A buffer overflow vulnerability in the vlc_input_attachment_New component of VideoLAN VLC Media Player
    3.0.11 allows attackers to cause an out-of-bounds read via a crafted .avi file. (CVE-2021-25803)

  - A NULL-pointer dereference in Open in avi.c of VideoLAN VLC Media Player 3.0.11 can a denial of service
    (DOS) in the application. (CVE-2021-25804)

  - An integer overflow in the VNC module in VideoLAN VLC Media Player through 3.0.17.4 allows attackers, by
    tricking a user into opening a crafted playlist or connecting to a rogue VNC server, to crash VLC or
    execute code under some conditions. (CVE-2022-41325)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6180-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13428");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-41325");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlccore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlccore8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlccore9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-access-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-fluidsynth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-notify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-skins2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-svg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-video-output");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-video-splitter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-visualization");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-zvbi");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libvlc-dev', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'libvlc5', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'libvlccore-dev', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'libvlccore8', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'vlc', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'vlc-data', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'vlc-nox', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'vlc-plugin-fluidsynth', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'vlc-plugin-jack', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'vlc-plugin-notify', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'vlc-plugin-samba', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'vlc-plugin-sdl', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'vlc-plugin-svg', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm2'},
    {'osver': '16.04', 'pkgname': 'vlc-plugin-zvbi', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm2'},
    {'osver': '18.04', 'pkgname': 'libvlc-bin', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libvlc-dev', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libvlc5', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libvlccore-dev', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libvlccore9', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc-bin', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc-data', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc-l10n', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-access-extra', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-base', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-fluidsynth', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-jack', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-notify', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-qt', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-samba', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-skins2', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-svg', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-video-output', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-video-splitter', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-visualization', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-zvbi', 'pkgver': '3.0.8-0ubuntu18.04.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libvlc-bin', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'libvlc-dev', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'libvlc5', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'libvlccore-dev', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'libvlccore9', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'vlc', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'vlc-bin', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'vlc-data', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'vlc-l10n', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-access-extra', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-base', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-fluidsynth', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-jack', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-notify', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-qt', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-samba', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-skins2', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-svg', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-video-output', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-video-splitter', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-visualization', 'pkgver': '3.0.9.2-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'libvlc-bin', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'libvlc-dev', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'libvlc5', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'libvlccore-dev', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'libvlccore9', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'vlc', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'vlc-bin', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'vlc-data', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'vlc-l10n', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-access-extra', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-base', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-fluidsynth', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-jack', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-notify', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-qt', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-samba', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-skins2', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-svg', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-video-output', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-video-splitter', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-visualization', 'pkgver': '3.0.16-1ubuntu0.1~esm1'},
    {'osver': '22.10', 'pkgname': 'libvlc-bin', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libvlc-dev', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libvlc5', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libvlccore-dev', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libvlccore9', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'vlc', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'vlc-bin', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'vlc-data', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'vlc-l10n', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'vlc-plugin-access-extra', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'vlc-plugin-base', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'vlc-plugin-fluidsynth', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'vlc-plugin-jack', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'vlc-plugin-notify', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'vlc-plugin-qt', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'vlc-plugin-samba', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'vlc-plugin-skins2', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'vlc-plugin-svg', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'vlc-plugin-video-output', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'vlc-plugin-video-splitter', 'pkgver': '3.0.17.4-5ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'vlc-plugin-visualization', 'pkgver': '3.0.17.4-5ubuntu0.1'}
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvlc-bin / libvlc-dev / libvlc5 / libvlccore-dev / libvlccore8 / etc');
}
