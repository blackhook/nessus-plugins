#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-793.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(137392);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_cve_id("CVE-2016-6328", "CVE-2017-7544", "CVE-2018-20030", "CVE-2019-9278", "CVE-2020-0093", "CVE-2020-12767", "CVE-2020-13112", "CVE-2020-13113", "CVE-2020-13114");

  script_name(english:"openSUSE Security Update : libexif (openSUSE-2020-793)");
  script_summary(english:"Check for the openSUSE-2020-793 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libexif to 0.6.22 fixes the following issues :

Security issues fixed :

  - CVE-2016-6328: Fixed an integer overflow in parsing
    MNOTE entry data of the input file (bsc#1055857).

  - CVE-2017-7544: Fixed an out-of-bounds heap read
    vulnerability in exif_data_save_data_entry function in
    libexif/exif-data.c (bsc#1059893).

  - CVE-2018-20030: Fixed a denial of service by endless
    recursion (bsc#1120943).

  - CVE-2019-9278: Fixed an integer overflow (bsc#1160770).

  - CVE-2020-0093: Fixed an out-of-bounds read in
    exif_data_save_data_entry (bsc#1171847).

  - CVE-2020-12767: Fixed a divide-by-zero error in
    exif_entry_get_value (bsc#1171475).

  - CVE-2020-13112: Fixed a time consumption DoS when
    parsing canon array markers (bsc#1172121).

  - CVE-2020-13113: Fixed a potential use of uninitialized
    memory (bsc#1172105).

  - CVE-2020-13114: Fixed various buffer overread fixes due
    to integer overflows in maker notes (bsc#1172116).

Non-security issues fixed :

  - libexif was updated to version 0.6.22 :

  - New translations: ms

  - Updated translations for most languages

  - Some useful EXIF 2.3 tag added :

  - EXIF_TAG_GAMMA

  - EXIF_TAG_COMPOSITE_IMAGE

  - EXIF_TAG_SOURCE_IMAGE_NUMBER_OF_COMPOSITE_IMAGE

  - EXIF_TAG_SOURCE_EXPOSURE_TIMES_OF_COMPOSITE_IMAGE

  - EXIF_TAG_GPS_H_POSITIONING_ERROR

  - EXIF_TAG_CAMERA_OWNER_NAME

  - EXIF_TAG_BODY_SERIAL_NUMBER

  - EXIF_TAG_LENS_SPECIFICATION

  - EXIF_TAG_LENS_MAKE

  - EXIF_TAG_LENS_MODEL

  - EXIF_TAG_LENS_SERIAL_NUMBER

This update was imported from the SUSE:SLE-15:Update update project."
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
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172121"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libexif packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9278");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexif-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexif-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexif-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexif12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexif12-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexif12-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexif12-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libexif-debugsource-0.6.22-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libexif-devel-0.6.22-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libexif12-0.6.22-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libexif12-debuginfo-0.6.22-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libexif-devel-32bit-0.6.22-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libexif12-32bit-0.6.22-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libexif12-32bit-debuginfo-0.6.22-lp151.4.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libexif-debugsource / libexif-devel / libexif12 / etc");
}
