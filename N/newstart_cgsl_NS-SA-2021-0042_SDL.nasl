##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0042. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147259);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

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
    "CVE-2019-7637",
    "CVE-2019-7638"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : SDL Multiple Vulnerabilities (NS-SA-2021-0042)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has SDL packages installed that are affected by
multiple vulnerabilities:

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    IMA_ADPCM_decode in audio/SDL_wave.c. (CVE-2019-7574)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a buffer over-read in
    SDL_LoadWAV_RW in audio/SDL_wave.c. (CVE-2019-7577)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    InitIMA_ADPCM in audio/SDL_wave.c. (CVE-2019-7578)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    Map1toN in video/SDL_pixels.c. (CVE-2019-7638)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    SDL_GetRGB in video/SDL_pixels.c. (CVE-2019-7636)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    Blit1to4 in video/SDL_blit_1.c. (CVE-2019-7635)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer overflow in
    SDL_FillRect in video/SDL_surface.c. (CVE-2019-7637)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer overflow in
    MS_ADPCM_decode in audio/SDL_wave.c. (CVE-2019-7575)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    InitMS_ADPCM in audio/SDL_wave.c (inside the wNumCoef loop). (CVE-2019-7573)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a buffer over-read in
    IMA_ADPCM_nibble in audio/SDL_wave.c. (CVE-2019-7572)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    InitMS_ADPCM in audio/SDL_wave.c (outside the wNumCoef loop). (CVE-2019-7576)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0042");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL SDL packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7638");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.04': [
    'SDL-1.2.15-17.el7',
    'SDL-devel-1.2.15-17.el7',
    'SDL-static-1.2.15-17.el7'
  ],
  'CGSL MAIN 5.04': [
    'SDL-1.2.15-17.el7',
    'SDL-devel-1.2.15-17.el7',
    'SDL-static-1.2.15-17.el7'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'SDL');
}
