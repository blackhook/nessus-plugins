#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:2322-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151738);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id(
    "CVE-2019-17539",
    "CVE-2020-13904",
    "CVE-2020-20448",
    "CVE-2020-20451",
    "CVE-2020-21041",
    "CVE-2020-22015",
    "CVE-2020-22016",
    "CVE-2020-22017",
    "CVE-2020-22019",
    "CVE-2020-22020",
    "CVE-2020-22021",
    "CVE-2020-22022",
    "CVE-2020-22023",
    "CVE-2020-22025",
    "CVE-2020-22026",
    "CVE-2020-22031",
    "CVE-2020-22032",
    "CVE-2020-22033",
    "CVE-2020-22034",
    "CVE-2020-22038",
    "CVE-2020-22039",
    "CVE-2020-22043",
    "CVE-2020-22044"
  );

  script_name(english:"openSUSE 15 Security Update : ffmpeg (openSUSE-SU-2021:2322-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:2322-1 advisory.

  - In FFmpeg before 4.2, avcodec_open2 in libavcodec/utils.c allows a NULL pointer dereference and possibly
    unspecified other impact when there is no valid close function pointer. (CVE-2019-17539)

  - FFmpeg 2.8 and 4.2.3 has a use-after-free via a crafted EXTINF duration in an m3u8 file because
    parse_playlist in libavformat/hls.c frees a pointer, and later that pointer is accessed in
    av_probe_input_format3 in libavformat/format.c. (CVE-2020-13904)

  - FFmpeg 4.1.3 is affected by a Divide By Zero issue via libavcodec/ratecontrol.c, which allows a remote
    malicious user to cause a Denial of Service. (CVE-2020-20448)

  - Denial of Service issue in FFmpeg 4.2 due to resource management errors via fftools/cmdutils.c.
    (CVE-2020-20451)

  - Buffer Overflow vulnerability exists in FFmpeg 4.1 via apng_do_inverse_blend in libavcodec/pngenc.c, which
    could let a remote malicious user cause a Denial of Service (CVE-2020-21041)

  - Buffer Overflow vulnerability in FFmpeg 4.2 in mov_write_video_tag due to the out of bounds in
    libavformat/movenc.c, which could let a remote malicious user obtain sensitive information, cause a Denial
    of Service, or execute arbitrary code. (CVE-2020-22015)

  - A heap-based Buffer Overflow vulnerability in FFmpeg 4.2 at libavcodec/get_bits.h when writing .mov files,
    which might lead to memory corruption and other potential consequences. (CVE-2020-22016)

  - A heap-based Buffer Overflow vulnerability exists in FFmpeg 4.2 at ff_fill_rectangle in
    libavfilter/drawutils.c, which might lead to memory corruption and other potential consequences.
    (CVE-2020-22017)

  - Buffer Overflow vulnerability in FFmpeg 4.2 at convolution_y_10bit in libavfilter/vf_vmafmotion.c, which
    could let a remote malicious user cause a Denial of Service. (CVE-2020-22019)

  - Buffer Overflow vulnerability in FFmpeg 4.2 in the build_diff_map function in libavfilter/vf_fieldmatch.c,
    which could let a remote malicious user cause a Denial of Service. (CVE-2020-22020)

  - Buffer Overflow vulnerability in FFmpeg 4.2 at filter_edges function in libavfilter/vf_yadif.c, which
    could let a remote malicious user cause a Denial of Service. (CVE-2020-22021)

  - A heap-based Buffer Overflow vulnerability exists in FFmpeg 4.2 in filter_frame at
    libavfilter/vf_fieldorder.c, which might lead to memory corruption and other potential consequences.
    (CVE-2020-22022)

  - A heap-based Buffer Overflow vulnerabililty exists in FFmpeg 4.2 in filter_frame at
    libavfilter/vf_bitplanenoise.c, which might lead to memory corruption and other potential consequences.
    (CVE-2020-22023)

  - A heap-based Buffer Overflow vulnerability exists in gaussian_blur at libavfilter/vf_edgedetect.c, which
    might lead to memory corruption and other potential consequences. (CVE-2020-22025)

  - Buffer Overflow vulnerability exists in FFmpeg 4.2 in the config_input function at
    libavfilter/af_tremolo.c, which could let a remote malicious user cause a Denial of Service.
    (CVE-2020-22026)

  - A Heap-based Buffer Overflow vulnerability exists in FFmpeg 4.2 at libavfilter/vf_w3fdif.c in
    filter16_complex_low, which might lead to memory corruption and other potential consequences.
    (CVE-2020-22031)

  - A heap-based Buffer Overflow vulnerability exists FFmpeg 4.2 at libavfilter/vf_edgedetect.c in
    gaussian_blur, which might lead to memory corruption and other potential consequences. (CVE-2020-22032)

  - A heap-based Buffer Overflow Vulnerability exists FFmpeg 4.2 at libavfilter/vf_vmafmotion.c in
    convolution_y_8bit, which could let a remote malicious user cause a Denial of Service. (CVE-2020-22033)

  - A heap-based Buffer Overflow vulnerability exists FFmpeg 4.2 at libavfilter/vf_floodfill.c, which might
    lead to memory corruption and other potential consequences. (CVE-2020-22034)

  - A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak in the
    ff_v4l2_m2m_create_context function in v4l2_m2m.c. (CVE-2020-22038)

  - A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak in the inavi_add_ientry
    function. (CVE-2020-22039)

  - A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak at the fifo_alloc_common
    function in libavutil/fifo.c. (CVE-2020-22043)

  - A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak in the
    url_open_dyn_buf_internal function in libavformat/aviobuf.c. (CVE-2020-22044)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186597");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186603");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186763");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MM55YS6XXAKFK3J35CDODMYMAZO6JX3S/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?900ad0a5");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17539");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-20448");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-20451");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21041");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22021");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22022");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22023");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22026");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22031");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22032");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22033");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22034");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22038");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22039");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22043");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22044");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17539");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

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
release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

pkgs = [
    {'reference':'ffmpeg-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ffmpeg-private-devel-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavcodec-devel-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavcodec57-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavcodec57-32bit-3.4.2-11.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavdevice-devel-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavdevice57-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavdevice57-32bit-3.4.2-11.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavfilter-devel-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavfilter6-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavfilter6-32bit-3.4.2-11.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavformat-devel-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavformat57-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavformat57-32bit-3.4.2-11.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavresample-devel-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavresample3-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavresample3-32bit-3.4.2-11.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavutil-devel-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavutil55-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavutil55-32bit-3.4.2-11.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpostproc-devel-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpostproc54-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpostproc54-32bit-3.4.2-11.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswresample-devel-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswresample2-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswresample2-32bit-3.4.2-11.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswscale-devel-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswscale4-3.4.2-11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswscale4-32bit-3.4.2-11.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  rpm_spec_vers_cmp = NULL;
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ffmpeg / ffmpeg-private-devel / libavcodec-devel / libavcodec57 / etc');
}
