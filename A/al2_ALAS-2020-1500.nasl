##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1500.
##

include('compat.inc');

if (description)
{
  script_id(141985);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/28");

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
  script_xref(name:"ALAS", value:"2020-1500");

  script_name(english:"Amazon Linux 2 : SDL (ALAS-2020-1500)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2020-1500 advisory.

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

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer overflow in
    SDL_FillRect in video/SDL_surface.c. (CVE-2019-7637)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in
    Map1toN in video/SDL_pixels.c. (CVE-2019-7638)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1500.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-7572");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-7573");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-7574");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-7575");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-7576");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-7577");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-7578");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-7635");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-7636");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-7637");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-7638");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update SDL' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7638");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:SDL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:SDL-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:SDL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:SDL-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'SDL-1.2.15-17.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'SDL-1.2.15-17.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'SDL-1.2.15-17.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'SDL-debuginfo-1.2.15-17.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'SDL-debuginfo-1.2.15-17.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'SDL-debuginfo-1.2.15-17.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'SDL-devel-1.2.15-17.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'SDL-devel-1.2.15-17.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'SDL-devel-1.2.15-17.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'SDL-static-1.2.15-17.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'SDL-static-1.2.15-17.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'SDL-static-1.2.15-17.amzn2', 'cpu':'x86_64', 'release':'AL2'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SDL / SDL-debuginfo / SDL-devel / etc");
}