#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:2919-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153007);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/04");

  script_cve_id(
    "CVE-2019-9721",
    "CVE-2020-21688",
    "CVE-2020-21697",
    "CVE-2020-22046",
    "CVE-2020-22048",
    "CVE-2020-22049",
    "CVE-2020-22054",
    "CVE-2021-38114"
  );

  script_name(english:"openSUSE 15 Security Update : ffmpeg (openSUSE-SU-2021:2919-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:2919-1 advisory.

  - A denial of service in the subtitle decoder in FFmpeg 3.2 and 4.1 allows attackers to hog the CPU via a
    crafted video file in Matroska format, because handle_open_brace in libavcodec/htmlsubtitles.c has a
    complex format argument to sscanf. (CVE-2019-9721)

  - A heap-use-after-free in the av_freep function in libavutil/mem.c of FFmpeg 4.2 allows attackers to
    execute arbitrary code. (CVE-2020-21688)

  - A heap-use-after-free in the mpeg_mux_write_packet function in libavformat/mpegenc.c of FFmpeg 4.2 allows
    to cause a denial of service (DOS) via a crafted avi file. (CVE-2020-21697)

  - A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak in the avpriv_float_dsp_allocl
    function in libavutil/float_dsp.c. (CVE-2020-22046)

  - A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak in the ff_frame_pool_get
    function in framepool.c. (CVE-2020-22048)

  - A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak in the wtvfile_open_sector
    function in wtvdec.c. (CVE-2020-22049)

  - A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak in the av_dict_set function in
    dict.c. (CVE-2020-22054)

  - libavcodec/dnxhddec.c in FFmpeg 4.4 does not check the return value of the init_vlc function, a similar
    issue to CVE-2013-0868. (CVE-2021-38114)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1129714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189350");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RHYNSW2TAJSSTZPOYXQXGZDI6LYBWIT4/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d09b6fa0");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9721");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21697");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22046");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22049");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22054");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38114");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-21688");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-private-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'ffmpeg-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ffmpeg-private-devel-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavcodec-devel-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavcodec57-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavcodec57-32bit-3.4.2-11.8.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavdevice-devel-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavdevice57-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavdevice57-32bit-3.4.2-11.8.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavfilter-devel-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavfilter6-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavfilter6-32bit-3.4.2-11.8.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavformat-devel-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavformat57-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavformat57-32bit-3.4.2-11.8.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavresample-devel-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavresample3-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavresample3-32bit-3.4.2-11.8.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavutil-devel-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavutil55-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavutil55-32bit-3.4.2-11.8.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpostproc-devel-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpostproc54-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpostproc54-32bit-3.4.2-11.8.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswresample-devel-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswresample2-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswresample2-32bit-3.4.2-11.8.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswscale-devel-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswscale4-3.4.2-11.8.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswscale4-32bit-3.4.2-11.8.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ffmpeg / ffmpeg-private-devel / libavcodec-devel / libavcodec57 / etc');
}
