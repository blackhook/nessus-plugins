#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1004.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117517);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-13300", "CVE-2018-15822");

  script_name(english:"openSUSE Security Update : ffmpeg-4 (openSUSE-2018-1004)");
  script_summary(english:"Check for the openSUSE-2018-1004 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ffmpeg-4 to version 4.0.2 fixes the following issues :

These security issues were fixed :

  - CVE-2018-15822: The flv_write_packet function did not
    check for an empty audio packet, leading to an assertion
    failure and DoS (bsc#1105869).

  - CVE-2018-13300: An improper argument passed to the
    avpriv_request_sample function may have triggered an
    out-of-array read while converting a crafted AVI file to
    MPEG4, leading to a denial of service and possibly an
    information disclosure (bsc#1100348).

These non-security issues were fixed :

  - Enable webvtt encoders and decoders (boo#1092241).

  - Build codec2 encoder and decoder, add libcodec2 to
    enable_decoders and enable_encoders.

  - Enable mpeg 1 and 2 encoders."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105869"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ffmpeg-4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libavcodec-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libavdevice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libavfilter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libavformat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libavresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libavutil-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libpostproc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libswresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libswscale-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-private-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec58-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec58-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec58-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice58-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice58-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice58-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter7-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter7-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat58-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat58-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat58-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil56-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil56-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc55-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc55-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc55-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"ffmpeg-4-debugsource-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"ffmpeg-4-libavcodec-devel-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"ffmpeg-4-libavdevice-devel-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"ffmpeg-4-libavfilter-devel-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"ffmpeg-4-libavformat-devel-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"ffmpeg-4-libavresample-devel-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"ffmpeg-4-libavutil-devel-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"ffmpeg-4-libpostproc-devel-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"ffmpeg-4-libswresample-devel-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"ffmpeg-4-libswscale-devel-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"ffmpeg-4-private-devel-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libavcodec58-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libavcodec58-debuginfo-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libavdevice58-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libavdevice58-debuginfo-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libavfilter7-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libavfilter7-debuginfo-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libavformat58-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libavformat58-debuginfo-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libavresample4-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libavresample4-debuginfo-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libavutil56-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libavutil56-debuginfo-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpostproc55-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpostproc55-debuginfo-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libswresample3-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libswresample3-debuginfo-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libswscale5-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libswscale5-debuginfo-4.0.2-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ffmpeg-4-debugsource-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ffmpeg-4-libavcodec-devel-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ffmpeg-4-libavdevice-devel-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ffmpeg-4-libavfilter-devel-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ffmpeg-4-libavformat-devel-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ffmpeg-4-libavresample-devel-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ffmpeg-4-libavutil-devel-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ffmpeg-4-libpostproc-devel-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ffmpeg-4-libswresample-devel-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ffmpeg-4-libswscale-devel-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ffmpeg-4-private-devel-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavcodec58-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavcodec58-debuginfo-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavdevice58-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavdevice58-debuginfo-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavfilter7-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavfilter7-debuginfo-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavformat58-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavformat58-debuginfo-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavresample4-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavresample4-debuginfo-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavutil56-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavutil56-debuginfo-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpostproc55-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpostproc55-debuginfo-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libswresample3-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libswresample3-debuginfo-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libswscale5-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libswscale5-debuginfo-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavcodec58-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavcodec58-debuginfo-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavdevice58-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavdevice58-debuginfo-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavfilter7-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavfilter7-debuginfo-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavformat58-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavformat58-debuginfo-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavresample4-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavresample4-debuginfo-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavutil56-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavutil56-debuginfo-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpostproc55-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpostproc55-debuginfo-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libswresample3-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libswresample3-debuginfo-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libswscale5-32bit-4.0.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libswscale5-debuginfo-32bit-4.0.2-13.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ffmpeg-4-debugsource / ffmpeg-4-libavcodec-devel / etc");
}
