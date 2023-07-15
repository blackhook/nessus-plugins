#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1361.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118867);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-1000223", "CVE-2018-17096", "CVE-2018-17097", "CVE-2018-17098");

  script_name(english:"openSUSE Security Update : soundtouch (openSUSE-2018-1361)");
  script_summary(english:"Check for the openSUSE-2018-1361 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for soundtouch fixes the following issues :

  - CVE-2018-17098: The WavFileBase class allowed remote
    attackers to cause a denial of service (heap corruption
    from size inconsistency) or possibly have unspecified
    other impact, as demonstrated by SoundStretch.
    (bsc#1108632)

  - CVE-2018-17097: The WavFileBase class allowed remote
    attackers to cause a denial of service (double free) or
    possibly have unspecified other impact, as demonstrated
    by SoundStretch. (double free) (bsc#1108631)

  - CVE-2018-17096: The BPMDetect class allowed remote
    attackers to cause a denial of service (assertion
    failure and application exit), as demonstrated by
    SoundStretch. (bsc#1108630)

  - CVE-2018-1000223: soundtouch contained a Buffer Overflow
    vulnerability in
    SoundStretch/WavFile.cpp:WavInFile::readHeaderBlock()
    that can result in arbitrary code execution. This attack
    appear to be exploitable via victim must open maliocius
    file in soundstretch utility. (boo#1103676)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108632"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected soundtouch packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSoundTouch0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSoundTouch0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSoundTouch0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSoundTouch0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:soundtouch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:soundtouch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:soundtouch-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:soundtouch-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/10");
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

if ( rpm_check(release:"SUSE42.3", reference:"libSoundTouch0-1.8.0-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libSoundTouch0-debuginfo-1.8.0-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"soundtouch-1.8.0-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"soundtouch-debuginfo-1.8.0-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"soundtouch-debugsource-1.8.0-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"soundtouch-devel-1.8.0-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSoundTouch0-32bit-1.8.0-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSoundTouch0-debuginfo-32bit-1.8.0-6.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libSoundTouch0 / libSoundTouch0-32bit / libSoundTouch0-debuginfo / etc");
}
