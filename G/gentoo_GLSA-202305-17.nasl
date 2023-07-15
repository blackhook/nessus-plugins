#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202305-17.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(175061);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/03");

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
    "CVE-2021-33657",
    "CVE-2022-34568"
  );

  script_name(english:"GLSA-202305-17 : libsdl: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202305-17 (libsdl: Multiple Vulnerabilities)

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

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    BlitNtoN in video/SDL_blit_N.c when called from SDL_SoftBlit in video/SDL_blit.c. (CVE-2019-13616)

  - There is a heap overflow problem in video/SDL_pixels.c in SDL (Simple DirectMedia Layer) 2.x to 2.0.18
    versions. By crafting a malicious .BMP file, an attacker can cause the application using this library to
    crash, denial of service or Code execution. (CVE-2021-33657)

  - SDL v1.2 was discovered to contain a use-after-free via the XFree function at /src/video/x11/SDL_x11yuv.c.
    (CVE-2022-34568)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202305-17");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=692388");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=836665");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=861809");
  script_set_attribute(attribute:"solution", value:
"All libsdl users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=media-libs/libsdl-1.2.15_p20221201");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33657");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libsdl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'media-libs/libsdl',
    'unaffected' : make_list("ge 1.2.15_p20221201"),
    'vulnerable' : make_list("lt 1.2.15_p20221201")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsdl');
}
