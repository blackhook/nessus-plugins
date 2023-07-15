#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:2919-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153011);
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
  script_xref(name:"SuSE", value:"SUSE-SU-2021:2919-1");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ffmpeg (SUSE-SU-2021:2919-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2021:2919-1 advisory.

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
  # https://lists.suse.com/pipermail/sle-security-updates/2021-September/009387.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?278d1998");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavcodec-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavcodec57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavdevice57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavfilter6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavformat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavformat57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavresample3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavresample3-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavutil-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavutil55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpostproc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpostproc54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libswresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libswresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libswscale-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libswscale4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'libavcodec57-3.4.2-11.8.2', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libavcodec57-3.4.2-11.8.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libavformat57-3.4.2-11.8.2', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libavformat57-3.4.2-11.8.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libavresample-devel-3.4.2-11.8.2', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libavresample-devel-3.4.2-11.8.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libavresample3-3.4.2-11.8.2', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libavresample3-3.4.2-11.8.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libavresample3-32bit-3.4.2-11.8.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libavresample3-32bit-3.4.2-11.8.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libavutil-devel-3.4.2-11.8.2', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libavutil-devel-3.4.2-11.8.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libavutil55-3.4.2-11.8.2', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libavutil55-3.4.2-11.8.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libpostproc-devel-3.4.2-11.8.2', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libpostproc-devel-3.4.2-11.8.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libpostproc54-3.4.2-11.8.2', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libpostproc54-3.4.2-11.8.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libswresample-devel-3.4.2-11.8.2', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libswresample-devel-3.4.2-11.8.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libswresample2-3.4.2-11.8.2', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libswresample2-3.4.2-11.8.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libswscale-devel-3.4.2-11.8.2', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libswscale-devel-3.4.2-11.8.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libswscale4-3.4.2-11.8.2', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libswscale4-3.4.2-11.8.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.2'},
    {'reference':'libavcodec57-3.4.2-11.8.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libavcodec57-3.4.2-11.8.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libavformat57-3.4.2-11.8.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libavformat57-3.4.2-11.8.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libavresample-devel-3.4.2-11.8.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libavresample-devel-3.4.2-11.8.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libavresample3-3.4.2-11.8.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libavresample3-3.4.2-11.8.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libavresample3-64bit-3.4.2-11.8.2', 'sp':'3', 'cpu':'aarch64_ilp32', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libavresample3-64bit-3.4.2-11.8.2', 'sp':'3', 'cpu':'aarch64_ilp32', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libavutil-devel-3.4.2-11.8.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libavutil-devel-3.4.2-11.8.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libavutil55-3.4.2-11.8.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libavutil55-3.4.2-11.8.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libpostproc-devel-3.4.2-11.8.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libpostproc-devel-3.4.2-11.8.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libpostproc54-3.4.2-11.8.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libpostproc54-3.4.2-11.8.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libswresample-devel-3.4.2-11.8.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libswresample-devel-3.4.2-11.8.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libswresample2-3.4.2-11.8.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libswresample2-3.4.2-11.8.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libswscale-devel-3.4.2-11.8.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libswscale-devel-3.4.2-11.8.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libswscale4-3.4.2-11.8.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'libswscale4-3.4.2-11.8.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-desktop-applications-release-15.3'},
    {'reference':'ffmpeg-3.4.2-11.8.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-packagehub-subpackages-release-15.2'},
    {'reference':'libavdevice57-3.4.2-11.8.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-packagehub-subpackages-release-15.2'},
    {'reference':'libavfilter6-3.4.2-11.8.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-packagehub-subpackages-release-15.2'},
    {'reference':'ffmpeg-3.4.2-11.8.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-packagehub-subpackages-release-15.3'},
    {'reference':'libavdevice57-3.4.2-11.8.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-packagehub-subpackages-release-15.3'},
    {'reference':'libavfilter6-3.4.2-11.8.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-packagehub-subpackages-release-15.3'},
    {'reference':'libavcodec-devel-3.4.2-11.8.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.2'},
    {'reference':'libavcodec-devel-3.4.2-11.8.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.2'},
    {'reference':'libavformat-devel-3.4.2-11.8.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.2'},
    {'reference':'libavformat-devel-3.4.2-11.8.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.2'},
    {'reference':'libavresample-devel-3.4.2-11.8.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.2'},
    {'reference':'libavresample-devel-3.4.2-11.8.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.2'},
    {'reference':'libavresample3-3.4.2-11.8.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.2'},
    {'reference':'libavresample3-3.4.2-11.8.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.2'},
    {'reference':'libavcodec-devel-3.4.2-11.8.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.3'},
    {'reference':'libavcodec-devel-3.4.2-11.8.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.3'},
    {'reference':'libavformat-devel-3.4.2-11.8.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.3'},
    {'reference':'libavformat-devel-3.4.2-11.8.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.3'},
    {'reference':'libavresample-devel-3.4.2-11.8.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.3'},
    {'reference':'libavresample-devel-3.4.2-11.8.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.3'},
    {'reference':'libavresample3-3.4.2-11.8.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.3'},
    {'reference':'libavresample3-3.4.2-11.8.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.3'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ffmpeg / libavcodec-devel / libavcodec57 / libavdevice57 / etc');
}
