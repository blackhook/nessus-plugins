#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-742.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111197);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-10017", "CVE-2018-11710");

  script_name(english:"openSUSE Security Update : libopenmpt (openSUSE-2018-742)");
  script_summary(english:"Check for the openSUSE-2018-742 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libopenmpt to version 0.3.9 fixes the following 
issues :

These security issues were fixed :

  - CVE-2018-11710: Prevent write near address 0 in
    out-of-memory situations when reading AMS files
    (bsc#1095644)

  - CVE-2018-10017: Preven out-of-bounds memory read with
    IT/ITP/MO3 files containing pattern loops (bsc#1089080)

These non-security issues were fixed :

  - [Bug] openmpt123: Fixed build failure in C++17 due to
    use of removed feature std::random_shuffle.

  - STM: Having both Bxx and Cxx commands in a pattern
    imported the Bxx command incorrectly.

  - STM: Last character of sample name was missing.

  - Speed up reading of truncated ULT files.

  - ULT: Portamento import was sometimes broken.

  - The resonant filter was sometimes unstable when
    combining low-volume samples, low cutoff and high mixing
    rates.

  - Keep track of active SFx macro during seeking.

  - The 'note cut' duplicate note action did not volume-ramp
    the previously playing sample.

  - A song starting with non-existing patterns could not be
    played.

  - DSM: Support restart position and 16-bit samples.

  - DTM: Import global volume.

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095644"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libopenmpt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt_modplug1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt_modplug1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt_modplug1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt_modplug1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openmpt123");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openmpt123-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libmodplug-devel-0.3.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmodplug1-0.3.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmodplug1-debuginfo-0.3.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libopenmpt-debugsource-0.3.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libopenmpt-devel-0.3.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libopenmpt0-0.3.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libopenmpt0-debuginfo-0.3.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libopenmpt_modplug1-0.3.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libopenmpt_modplug1-debuginfo-0.3.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"openmpt123-0.3.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"openmpt123-debuginfo-0.3.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libmodplug1-32bit-0.3.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libmodplug1-32bit-debuginfo-0.3.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libopenmpt0-32bit-0.3.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libopenmpt0-32bit-debuginfo-0.3.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libopenmpt_modplug1-32bit-0.3.9-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libopenmpt_modplug1-32bit-debuginfo-0.3.9-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmodplug-devel / libmodplug1 / libmodplug1-debuginfo / etc");
}
