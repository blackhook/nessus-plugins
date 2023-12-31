#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-449.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99260);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-10190");

  script_name(english:"openSUSE Security Update : ffmpeg (openSUSE-2017-449)");
  script_summary(english:"Check for the openSUSE-2017-449 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ffmpeg fixes the following issues :

Security issue fixed :

  - CVE-2016-10190: remote code execution vulnerability [ 1
    - libavformat/http.c ] (boo#1022920)

Detailed ChangeLog :

  - 3.1.6:
    https://github.com/FFmpeg/FFmpeg/blob/e08b1cf2df8cfdb339
    4aa5ab0320739f8b5a1c4f/Changelog

  - 3.2.4:
    https://github.com/FFmpeg/FFmpeg/blob/cbe65ccfa02a9061ce
    ad73a6685eef90225c41b5/Changelog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022920"
  );
  # https://github.com/FFmpeg/FFmpeg/blob/cbe65ccfa02a9061cead73a6685eef90225c41b5/Changelog
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f9e96e4"
  );
  # https://github.com/FFmpeg/FFmpeg/blob/e08b1cf2df8cfdb3394aa5ab0320739f8b5a1c4f/Changelog
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff9f3506"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ffmpeg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"ffmpeg-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ffmpeg-debuginfo-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ffmpeg-debugsource-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavcodec-devel-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavcodec57-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavcodec57-debuginfo-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavdevice-devel-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavdevice57-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavdevice57-debuginfo-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavfilter-devel-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavfilter6-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavfilter6-debuginfo-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavformat-devel-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavformat57-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavformat57-debuginfo-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavresample-devel-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavresample3-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavresample3-debuginfo-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavutil-devel-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavutil55-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavutil55-debuginfo-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpostproc-devel-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpostproc54-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpostproc54-debuginfo-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswresample-devel-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswresample2-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswresample2-debuginfo-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswscale-devel-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswscale4-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswscale4-debuginfo-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavcodec57-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavcodec57-debuginfo-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavdevice57-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavdevice57-debuginfo-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavfilter6-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavfilter6-debuginfo-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavformat57-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavformat57-debuginfo-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavresample3-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavresample3-debuginfo-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavutil55-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavutil55-debuginfo-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpostproc54-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpostproc54-debuginfo-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libswresample2-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libswresample2-debuginfo-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libswscale4-32bit-3.2.4-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libswscale4-debuginfo-32bit-3.2.4-6.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ffmpeg / ffmpeg-debuginfo / ffmpeg-debugsource / libavcodec-devel / etc");
}
