#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1012-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151525);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/13");

  script_cve_id("CVE-2021-3185");

  script_name(english:"openSUSE 15 Security Update : gstreamer-plugins-bad (openSUSE-SU-2021:1012-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by a vulnerability as referenced in the
openSUSE-SU-2021:1012-1 advisory.

  - A flaw was found in the gstreamer h264 component of gst-plugins-bad before v1.18.1 where when parsing a
    h264 header, an attacker could cause the stack to be smashed, memory corruption and possibly code
    execution. (CVE-2021-3185)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181255");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2B2UD46YGBOYO64SOPMOM6DQAL6FGCHZ/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8a80ac1");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3185");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3185");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-chromaprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-chromaprint-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-chromaprint-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-fluidsynth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-fluidsynth-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-fluidsynth-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstadaptivedemux-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstadaptivedemux-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstadaptivedemux-1_0-0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbadaudio-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbadaudio-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbadaudio-1_0-0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbasecamerabinsrc-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbasecamerabinsrc-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbasecamerabinsrc-1_0-0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstcodecparsers-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstcodecparsers-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstcodecparsers-1_0-0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstinsertbin-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstinsertbin-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstinsertbin-1_0-0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstisoff-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstisoff-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstisoff-1_0-0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstmpegts-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstmpegts-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstmpegts-1_0-0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstphotography-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstphotography-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstphotography-1_0-0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstplayer-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstplayer-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstplayer-1_0-0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstsctp-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstsctp-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstsctp-1_0-0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsturidownloader-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsturidownloader-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsturidownloader-1_0-0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwayland-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwayland-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwayland-1_0-0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwebrtc-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwebrtc-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwebrtc-1_0-0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstInsertBin-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstMpegts-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstPlayer-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstWebRTC-1_0");
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
    {'reference':'gstreamer-plugins-bad-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer-plugins-bad-32bit-1.16.3-lp153.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer-plugins-bad-64bit-1.16.3-lp153.3.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer-plugins-bad-chromaprint-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer-plugins-bad-chromaprint-32bit-1.16.3-lp153.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer-plugins-bad-chromaprint-64bit-1.16.3-lp153.3.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer-plugins-bad-devel-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer-plugins-bad-fluidsynth-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer-plugins-bad-fluidsynth-32bit-1.16.3-lp153.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer-plugins-bad-fluidsynth-64bit-1.16.3-lp153.3.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer-plugins-bad-lang-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstadaptivedemux-1_0-0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstadaptivedemux-1_0-0-32bit-1.16.3-lp153.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstadaptivedemux-1_0-0-64bit-1.16.3-lp153.3.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstbadaudio-1_0-0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstbadaudio-1_0-0-32bit-1.16.3-lp153.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstbadaudio-1_0-0-64bit-1.16.3-lp153.3.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstbasecamerabinsrc-1_0-0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstbasecamerabinsrc-1_0-0-32bit-1.16.3-lp153.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstbasecamerabinsrc-1_0-0-64bit-1.16.3-lp153.3.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstcodecparsers-1_0-0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstcodecparsers-1_0-0-32bit-1.16.3-lp153.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstcodecparsers-1_0-0-64bit-1.16.3-lp153.3.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstinsertbin-1_0-0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstinsertbin-1_0-0-32bit-1.16.3-lp153.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstinsertbin-1_0-0-64bit-1.16.3-lp153.3.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstisoff-1_0-0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstisoff-1_0-0-32bit-1.16.3-lp153.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstisoff-1_0-0-64bit-1.16.3-lp153.3.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstmpegts-1_0-0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstmpegts-1_0-0-32bit-1.16.3-lp153.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstmpegts-1_0-0-64bit-1.16.3-lp153.3.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstphotography-1_0-0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstphotography-1_0-0-32bit-1.16.3-lp153.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstphotography-1_0-0-64bit-1.16.3-lp153.3.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstplayer-1_0-0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstplayer-1_0-0-32bit-1.16.3-lp153.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstplayer-1_0-0-64bit-1.16.3-lp153.3.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstsctp-1_0-0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstsctp-1_0-0-32bit-1.16.3-lp153.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstsctp-1_0-0-64bit-1.16.3-lp153.3.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgsturidownloader-1_0-0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgsturidownloader-1_0-0-32bit-1.16.3-lp153.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgsturidownloader-1_0-0-64bit-1.16.3-lp153.3.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstwayland-1_0-0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstwayland-1_0-0-32bit-1.16.3-lp153.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstwayland-1_0-0-64bit-1.16.3-lp153.3.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstwebrtc-1_0-0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstwebrtc-1_0-0-32bit-1.16.3-lp153.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgstwebrtc-1_0-0-64bit-1.16.3-lp153.3.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'typelib-1_0-GstInsertBin-1_0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'typelib-1_0-GstMpegts-1_0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'typelib-1_0-GstPlayer-1_0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'typelib-1_0-GstWebRTC-1_0-1.16.3-lp153.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gstreamer-plugins-bad / gstreamer-plugins-bad-32bit / etc');
}
