##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3868 and
# CentOS Errata and Security Advisory 2020:3868 respectively.
##

include('compat.inc');

if (description)
{
  script_id(141585);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

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
  script_xref(name:"RHSA", value:"2020:3868");

  script_name(english:"CentOS 7 : SDL (CESA-2020:3868)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:3868 advisory.

  - SDL: buffer over-read in IMA_ADPCM_nibble in audio/SDL_wave.c (CVE-2019-7572)

  - SDL: heap-based buffer over-read in InitMS_ADPCM in audio/SDL_wave.c (CVE-2019-7573, CVE-2019-7576)

  - SDL: heap-based buffer over-read in IMA_ADPCM_decode in audio/SDL_wave.c (CVE-2019-7574)

  - SDL: heap-based buffer overflow in MS_ADPCM_decode in audio/SDL_wave.c (CVE-2019-7575)

  - SDL: buffer over-read in SDL_LoadWAV_RW in audio/SDL_wave.c (CVE-2019-7577)

  - SDL: heap-based buffer over-read in InitIMA_ADPCM in audio/SDL_wave.c (CVE-2019-7578)

  - SDL: heap-based buffer over-read in Blit1to4 in video/SDL_blit_1.c (CVE-2019-7635)

  - SDL: heap-based buffer over-read in SDL_GetRGB in video/SDL_pixels.c (CVE-2019-7636)

  - SDL: heap-based buffer overflow in SDL_FillRect in video/SDL_surface.c (CVE-2019-7637)

  - SDL: heap-based buffer over-read in Map1toN in video/SDL_pixels.c (CVE-2019-7638)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-October/012834.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c78ed54");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/120.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/122.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/125.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected SDL, SDL-devel and / or SDL-static packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7638");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(120, 122, 125);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:SDL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:SDL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:SDL-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'SDL-1.2.15-17.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'SDL-1.2.15-17.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'SDL-devel-1.2.15-17.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'SDL-devel-1.2.15-17.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'SDL-static-1.2.15-17.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'SDL-static-1.2.15-17.el7', 'cpu':'x86_64', 'release':'CentOS-7'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +
    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'SDL / SDL-devel / SDL-static');
}
