#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-86.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106325);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-6328", "CVE-2017-7544");

  script_name(english:"openSUSE Security Update : libexif (openSUSE-2018-86)");
  script_summary(english:"Check for the openSUSE-2018-86 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libexif fixes several issues.

These security issues were fixed :

  - CVE-2016-6328: Fixed integer overflow in parsing MNOTE
    entry data of the input file (bsc#1055857)

  - CVE-2017-7544: Fixed out-of-bounds heap read
    vulnerability in exif_data_save_data_entry function in
    libexif/exif-data.c caused by improper length
    computation of the allocated data of an ExifMnote entry
    which can cause denial-of-service or possibly
    information disclosure (bsc#1059893)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059893"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libexif packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexif-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexif-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexif12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexif12-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexif12-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexif12-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/25");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libexif-debugsource-0.6.21-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libexif-devel-0.6.21-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libexif12-0.6.21-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libexif12-debuginfo-0.6.21-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libexif12-32bit-0.6.21-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libexif12-debuginfo-32bit-0.6.21-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libexif-debugsource-0.6.21-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libexif-devel-0.6.21-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libexif12-0.6.21-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libexif12-debuginfo-0.6.21-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libexif12-32bit-0.6.21-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libexif12-debuginfo-32bit-0.6.21-15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libexif-debugsource / libexif-devel / libexif12 / libexif12-32bit / etc");
}
