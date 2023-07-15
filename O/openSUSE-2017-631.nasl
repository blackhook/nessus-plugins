#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-631.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100504);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-10190", "CVE-2016-10191", "CVE-2016-10192", "CVE-2016-9561", "CVE-2017-7863", "CVE-2017-7865", "CVE-2017-7866");

  script_name(english:"openSUSE Security Update : ffmpeg2 (openSUSE-2017-631)");
  script_summary(english:"Check for the openSUSE-2017-631 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ffmpeg2 fixes security issues, bugs, and enables AC3
and MP3 decoding.

The following vulnerabilities were fixed :

  - CVE-2017-7863: heap-based buffer overflow (bsc#1034179)

  - CVE-2017-7865: heap-based buffer overflow (bsc#1034177)

  - CVE-2017-7866: stack-based buffer overflow (bsc#1034176)

  - CVE-2016-10191: remote code execution (bsc#1022921)

  - CVE-2016-10190: remote code execution (bsc#1022920)

  - CVE-2016-10192: remote code execution (bsc#1022922)

  - CVE-2016-9561: Huge amount memory allocated, resulting
    in DoS of ffmpeg (bsc#1015120)

The following functionality was added :

  - Enable AC3 and MP3 decoding

ffmpeg was updated to 2.8.11, containing a number of upstream
improvements and fixes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034179"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ffmpeg2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec56-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec56-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice56-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice56-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat56-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat56-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil54-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil54-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil54-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc53-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc53-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc53-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/30");
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

if ( rpm_check(release:"SUSE42.2", reference:"ffmpeg2-debugsource-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ffmpeg2-devel-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavcodec56-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavcodec56-debuginfo-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavdevice56-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavdevice56-debuginfo-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavfilter5-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavfilter5-debuginfo-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavformat56-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavformat56-debuginfo-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavresample2-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavresample2-debuginfo-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavutil54-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavutil54-debuginfo-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpostproc53-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpostproc53-debuginfo-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswresample1-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswresample1-debuginfo-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswscale3-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswscale3-debuginfo-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavcodec56-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavcodec56-debuginfo-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavdevice56-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavdevice56-debuginfo-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavfilter5-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavfilter5-debuginfo-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavformat56-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavformat56-debuginfo-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavresample2-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavresample2-debuginfo-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavutil54-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavutil54-debuginfo-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpostproc53-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpostproc53-debuginfo-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libswresample1-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libswresample1-debuginfo-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libswscale3-32bit-2.8.11-25.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libswscale3-debuginfo-32bit-2.8.11-25.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ffmpeg2-debugsource / ffmpeg2-devel / libavcodec56 / etc");
}
