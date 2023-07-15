#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-153.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145305);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/27");

  script_cve_id("CVE-2018-10536", "CVE-2018-10537", "CVE-2018-10538", "CVE-2018-10539", "CVE-2018-10540", "CVE-2018-19840", "CVE-2018-19841", "CVE-2018-6767", "CVE-2018-7253", "CVE-2018-7254", "CVE-2019-1010319", "CVE-2019-11498", "CVE-2020-35738");

  script_name(english:"openSUSE Security Update : wavpack (openSUSE-2021-153)");
  script_summary(english:"Check for the openSUSE-2021-153 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for wavpack fixes the following issues :

  - Update to version 5.4.0

  - CVE-2020-35738: Fixed an out-of-bounds write in
    WavpackPackSamples (bsc#1180414) 

  - fixed: disable A32 asm code when building for Apple
    silicon

  - fixed: issues with Adobe-style floating-point WAV files

  - added: --normalize-floats option to wvunpack for
    correctly exporting un-normalized floating-point files

  - Update to version 5.3.0 

  - fixed: OSS-Fuzz issues 19925, 19928, 20060, 20448

  - fixed: trailing garbage characters on imported ID3v2
    TXXX tags

  - fixed: various minor undefined behavior and memory
    access issues

  - fixed: sanitize tag extraction names for length and path
    inclusion

  - improved: reformat wvunpack 'help' and split into long +
    short versions

  - added: regression testing to Travis CI for OSS-Fuzz
    crashers

  - Updated to version 5.2.0 

    *fixed: potential security issues including the
    following CVEs: CVE-2018-19840, CVE-2018-19841,
    CVE-2018-10536 (bsc#1091344), CVE-2018-10537
    (bsc#1091343) CVE-2018-10538 (bsc#1091342),
    CVE-2018-10539 (bsc#1091341), CVE-2018-10540
    (bsc#1091340), CVE-2018-7254, CVE-2018-7253,
    CVE-2018-6767, CVE-2019-11498 and CVE-2019-1010319

  - added: support for CMake, Travis CI, and Google's
    OSS-fuzz

  - fixed: use correction file for encode verify (pipe
    input, Windows)

  - fixed: correct WAV header with actual length (pipe
    input, -i option)

  - fixed: thumb interworking and not needing v6
    architecture (ARM asm)

  - added: handle more ID3v2.3 tag items and from all file
    types

  - fixed: coredump on Sparc64 (changed MD5 implementation)

  - fixed: handle invalid ID3v2.3 tags from sacd-ripper

  - fixed: several corner-case memory leaks

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180414"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected wavpack packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwavpack1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwavpack1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwavpack1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwavpack1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wavpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wavpack-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wavpack-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wavpack-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libwavpack1-5.4.0-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libwavpack1-debuginfo-5.4.0-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"wavpack-5.4.0-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"wavpack-debuginfo-5.4.0-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"wavpack-debugsource-5.4.0-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"wavpack-devel-5.4.0-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libwavpack1-32bit-5.4.0-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libwavpack1-32bit-debuginfo-5.4.0-lp152.7.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwavpack1 / libwavpack1-debuginfo / wavpack / wavpack-debuginfo / etc");
}
