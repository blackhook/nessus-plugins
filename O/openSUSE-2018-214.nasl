#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-214.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107048);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-9100", "CVE-2015-9101", "CVE-2017-11720", "CVE-2017-13712", "CVE-2017-15019", "CVE-2017-9410", "CVE-2017-9411", "CVE-2017-9412", "CVE-2017-9869", "CVE-2017-9870", "CVE-2017-9871", "CVE-2017-9872");

  script_name(english:"openSUSE Security Update : lame (openSUSE-2018-214)");
  script_summary(english:"Check for the openSUSE-2018-214 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for lame fixes the following issues :

Lame was updated to version 3.100 :

  - Improved detection of MPEG audio data in RIFF WAVE
    files. sf#3545112 Invalid sampling detection

  - New switch --gain <decibel>, range -20.0 to +12.0, a
    more convenient way to apply Gain adjustment in
    decibels, than the use of --scale <factor>.

  - Fix for sf#3558466 Bug in path handling

  - Fix for sf#3567844 problem with Tag genre

  - Fix for sf#3565659 no progress indication with pipe
    input

  - Fix for sf#3544957 scale (empty) silent encode without
    warning

  - Fix for sf#3580176 environment variable LAMEOPT doesn't
    work anymore

  - Fix for sf#3608583 input file name displayed with wrong
    character encoding (on windows console with CP_UTF8)

  - Fix dereference NULL and Buffer not NULL terminated
    issues. (CVE-2017-15019 bsc#1082317 CVE-2017-13712
    bsc#1082399 CVE-2015-9100 bsc#1082401)

  - Fix dereference of a NULL pointer possible in loop.

  - Make sure functions with SSE instructions maintain their
    own properly aligned stack. Thanks to Fabian Greffrath

  - Multiple Stack and Heap Corruptions from Malicious File.
    (CVE-2017-9872 bsc#1082391 CVE-2017-9871 bsc#1082392
    CVE-2017-9870 bsc#1082393 CVE-2017-9869 bsc#1082395
    CVE-2017-9411 bsc#1082397 CVE-2015-9101 bsc#1082400)

  - CVE-2017-11720: Fix a division by zero vulnerability.
    (bsc#1082311)

  - CVE-2017-9410: Fix fill_buffer_resample function in
    libmp3lame/util.c heap-based buffer over-read and ap
    (bsc#1082333)

  - CVE-2017-9411: Fix fill_buffer_resample function in
    libmp3lame/util.c invalid memory read and application
    crash (bsc#1082397)

  - CVE-2017-9412: FIx unpack_read_samples function in
    frontend/get_audio.c invalid memory read and application
    crash (bsc#1082340)

  - Fix clip detect scale suggestion unaware of scale input
    value

  - HIP decoder bug fixed: decoding mixed blocks of lower
    sample frequency Layer3 data resulted in internal buffer
    overflow.

  - Add lame_encode_buffer_interleaved_int()"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082401"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lame packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lame");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lame-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lame-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lame-mp3rtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lame-mp3rtp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmp3lame-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmp3lame0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmp3lame0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmp3lame0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmp3lame0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"lame-3.100-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lame-debuginfo-3.100-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lame-debugsource-3.100-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lame-mp3rtp-3.100-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lame-mp3rtp-debuginfo-3.100-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmp3lame-devel-3.100-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmp3lame0-3.100-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmp3lame0-debuginfo-3.100-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmp3lame0-32bit-3.100-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmp3lame0-debuginfo-32bit-3.100-7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lame / lame-debuginfo / lame-debugsource / lame-mp3rtp / etc");
}
