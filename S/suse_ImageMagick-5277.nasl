#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ImageMagick-5277.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(33379);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-1096", "CVE-2008-1097");

  script_name(english:"openSUSE 10 Security Update : ImageMagick (ImageMagick-5277)");
  script_summary(english:"Check for the ImageMagick-5277 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ImageMagick is affected by two security problems :

CVE-2008-1096: Buffer overflow in the handling of XCF files
CVE-2008-1097: Heap buffer overflow in the handling of PCX files"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ImageMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-Magick++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-Magick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libWand10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PerlMagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"ImageMagick-6.2.5-16.29") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"ImageMagick-Magick++-6.2.5-16.29") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"ImageMagick-Magick++-devel-6.2.5-16.29") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"ImageMagick-devel-6.2.5-16.29") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"perl-PerlMagick-6.2.5-16.29") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ImageMagick-6.3.0.0-27.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ImageMagick-Magick++-6.3.0.0-27.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ImageMagick-Magick++-devel-6.3.0.0-27.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ImageMagick-devel-6.3.0.0-27.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"perl-PerlMagick-6.3.0.0-27.10") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ImageMagick-6.3.5.10-2.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ImageMagick-devel-6.3.5.10-2.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ImageMagick-extra-6.3.5.10-2.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libMagick++-devel-6.3.5.10-2.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libMagick++10-6.3.5.10-2.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libMagick10-6.3.5.10-2.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libWand10-6.3.5.10-2.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"perl-PerlMagick-6.3.5.10-2.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
