#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1142.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103764);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-10507", "CVE-2017-14039", "CVE-2017-14040", "CVE-2017-14041", "CVE-2017-14164");

  script_name(english:"openSUSE Security Update : openjpeg2 (openSUSE-2017-1142)");
  script_summary(english:"Check for the openSUSE-2017-1142 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openjpeg2 fixes several issues.

These security issues were fixed :

  - CVE-2016-10507: Integer overflow vulnerability in the
    bmp24toimage function allowed remote attackers to cause
    a denial of service (heap-based buffer over-read and
    application crash) via a crafted bmp file (bsc#1056421).

  - CVE-2017-14039: A heap-based buffer overflow was
    discovered in the opj_t2_encode_packet function. The
    vulnerability caused an out-of-bounds write, which may
    have lead to remote denial of service or possibly
    unspecified other impact (bsc#1056622).

  - CVE-2017-14164: A size-validation issue was discovered
    in opj_j2k_write_sot. The vulnerability caused an
    out-of-bounds write, which may have lead to remote DoS
    or possibly remote code execution (bsc#1057511).

  - CVE-2017-14040: An invalid write access was discovered
    in bin/jp2/convert.c, triggering a crash in the
    tgatoimage function. The vulnerability may have lead to
    remote denial of service or possibly unspecified other
    impact (bsc#1056621).

  - CVE-2017-14041: A stack-based buffer overflow was
    discovered in the pgxtoimage function. The vulnerability
    caused an out-of-bounds write, which may have lead to
    remote denial of service or possibly remote code
    execution (bsc#1056562).

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057511"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openjpeg2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenjp2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenjp2-7-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenjp2-7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenjp2-7-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openjpeg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openjpeg2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openjpeg2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openjpeg2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/11");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libopenjp2-7-2.1.0-13.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libopenjp2-7-debuginfo-2.1.0-13.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openjpeg2-2.1.0-13.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openjpeg2-debuginfo-2.1.0-13.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openjpeg2-debugsource-2.1.0-13.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openjpeg2-devel-2.1.0-13.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libopenjp2-7-32bit-2.1.0-13.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libopenjp2-7-debuginfo-32bit-2.1.0-13.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libopenjp2-7-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libopenjp2-7-debuginfo-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openjpeg2-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openjpeg2-debuginfo-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openjpeg2-debugsource-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openjpeg2-devel-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libopenjp2-7-32bit-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libopenjp2-7-debuginfo-32bit-2.1.0-19.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopenjp2-7 / libopenjp2-7-32bit / libopenjp2-7-debuginfo / etc");
}
