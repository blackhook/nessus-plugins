#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3314. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171377);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/11");

  script_cve_id(
    "CVE-2019-7572",
    "CVE-2019-7573",
    "CVE-2019-7574",
    "CVE-2019-7575",
    "CVE-2019-7576",
    "CVE-2019-7577",
    "CVE-2019-7578",
    "CVE-2019-7635",
    "CVE-2019-7636",
    "CVE-2019-7638",
    "CVE-2019-13616",
    "CVE-2019-13626",
    "CVE-2020-14409",
    "CVE-2020-14410",
    "CVE-2021-33657",
    "CVE-2022-4743"
  );

  script_name(english:"Debian DLA-3314-1 : libsdl2 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3314 advisory.

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    BlitNtoN in video/SDL_blit_N.c when called from SDL_SoftBlit in video/SDL_blit.c. (CVE-2019-13616)

  - SDL (Simple DirectMedia Layer) 2.x through 2.0.9 has a heap-based buffer over-read in
    Fill_IMA_ADPCM_block, caused by an integer overflow in IMA_ADPCM_decode() in audio/SDL_wave.c.
    (CVE-2019-13626)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a buffer over-read in
    IMA_ADPCM_nibble in audio/SDL_wave.c. (CVE-2019-7572)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    InitMS_ADPCM in audio/SDL_wave.c (inside the wNumCoef loop). (CVE-2019-7573)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    IMA_ADPCM_decode in audio/SDL_wave.c. (CVE-2019-7574)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer overflow in
    MS_ADPCM_decode in audio/SDL_wave.c. (CVE-2019-7575)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    InitMS_ADPCM in audio/SDL_wave.c (outside the wNumCoef loop). (CVE-2019-7576)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a buffer over-read in
    SDL_LoadWAV_RW in audio/SDL_wave.c. (CVE-2019-7577)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    InitIMA_ADPCM in audio/SDL_wave.c. (CVE-2019-7578)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    Blit1to4 in video/SDL_blit_1.c. (CVE-2019-7635)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    SDL_GetRGB in video/SDL_pixels.c. (CVE-2019-7636)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    Map1toN in video/SDL_pixels.c. (CVE-2019-7638)

  - SDL (Simple DirectMedia Layer) through 2.0.12 has an Integer Overflow (and resultant SDL_memcpy heap
    corruption) in SDL_BlitCopy in video/SDL_blit_copy.c via a crafted .BMP file. (CVE-2020-14409)

  - SDL (Simple DirectMedia Layer) through 2.0.12 has a heap-based buffer over-read in
    Blit_3or4_to_3or4__inversed_rgb in video/SDL_blit_N.c via a crafted .BMP file. (CVE-2020-14410)

  - There is a heap overflow problem in video/SDL_pixels.c in SDL (Simple DirectMedia Layer) 2.x to 2.0.18
    versions. By crafting a malicious .BMP file, an attacker can cause the application using this library to
    crash, denial of service or Code execution. (CVE-2021-33657)

  - A potential memory leak issue was discovered in SDL2 in GLES_CreateTexture() function in
    SDL_render_gles.c. The vulnerability allows an attacker to cause a denial of service attack. The
    vulnerability affects SDL2 v2.0.4 and above. SDL-1.x are not affected. (CVE-2022-4743)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=924610");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libsdl2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3314");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13616");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13626");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-7572");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-7573");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-7574");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-7575");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-7576");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-7577");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-7578");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-7635");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-7636");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-7638");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-14409");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-14410");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33657");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4743");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/libsdl2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libsdl2 packages.

For Debian 10 buster, these problems have been fixed in version 2.0.9+dfsg1-1+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33657");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsdl2-2.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsdl2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsdl2-doc");
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
    {'release': '10.0', 'prefix': 'libsdl2-2.0-0', 'reference': '2.0.9+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libsdl2-dev', 'reference': '2.0.9+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libsdl2-doc', 'reference': '2.0.9+dfsg1-1+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsdl2-2.0-0 / libsdl2-dev / libsdl2-doc');
}
