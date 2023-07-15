#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-306.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108633);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : libmodplug (openSUSE-2018-306)");
  script_summary(english:"Check for the openSUSE-2018-306 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libmodplug fixes the following issues :

Several security and non security issues where fixed :

  - Update to version 0.8.9.0+git20170610.f6dd59a
    boo#1022032 :

  - PSM: add missing line to commit

  - ABC: prevent possible increment of p past end

  - ABC: ensure read pointer is valid before incrementing

  - ABC: terminate early when things don't work in
    substitute

  - OKT: add one more bound check

  - FAR: out by one on check

  - ABC: 10 digit ints require null termination

  - PSM: make sure reads occur of only valid ins

  - ABC: cleanup tracks correctly.

  - WAV: check that there is space for both headers

  - OKT: ensure file size is enough to contain data

  - ABC: initialize earlier

  - ABC: ensure array access is bounded correctly.

  - ABC: clean up loop exiting code

  - ABC: avoid possibility of incrementing *p

  - ABC: abort early if macro would be blank

  - ABC: Use blankline more often

  - ABC: Ensure for loop does not increment past end of loop

  - Initialize nPatterns to 0 earlier

  - Check memory position isn't over the memory length

  - ABC: transpose only needs to look at notes (<26)

  - Spelling fixes

  - Bump version number to 0.8.9.0

  - MMCMP: Check that end pointer is within the file size

  - WAV: ensure integer doesn't overflow

  - XM: additional mempos check

  - sndmix: Don't process row if its empty.

  - snd_fx: dont include patterns of zero size in length
    calc

  - MT2,AMF: prevent OOB reads"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022032"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libmodplug packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.3", reference:"libmodplug-debugsource-0.8.9.0+git20170610.f6dd59a-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmodplug-devel-0.8.9.0+git20170610.f6dd59a-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmodplug1-0.8.9.0+git20170610.f6dd59a-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmodplug1-debuginfo-0.8.9.0+git20170610.f6dd59a-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmodplug1-32bit-0.8.9.0+git20170610.f6dd59a-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmodplug1-debuginfo-32bit-0.8.9.0+git20170610.f6dd59a-8.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmodplug-debugsource / libmodplug-devel / libmodplug1 / etc");
}
