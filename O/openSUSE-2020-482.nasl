#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-482.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(135384);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/14");

  script_cve_id("CVE-2017-1000126", "CVE-2017-9239", "CVE-2018-12264", "CVE-2018-12265", "CVE-2018-17229", "CVE-2018-17230", "CVE-2018-17282", "CVE-2018-19108", "CVE-2018-19607", "CVE-2018-9305", "CVE-2019-13114");

  script_name(english:"openSUSE Security Update : exiv2 (openSUSE-2020-482)");
  script_summary(english:"Check for the openSUSE-2020-482 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for exiv2 fixes the following issues :

exiv2 was updated to latest 0.26 branch, fixing bugs and security
issues :

  - CVE-2017-1000126: Fixed an out of bounds read in webp
    parser (bsc#1068873).

  - CVE-2017-9239: Fixed a segmentation fault in
    TiffImageEntry::doWriteImage function (bsc#1040973).

  - CVE-2018-12264: Fixed an integer overflow in
    LoaderTiff::getData() which might have led to an
    out-of-bounds read (bsc#1097600).

  - CVE-2018-12265: Fixed integer overflows in
    LoaderExifJpeg which could have led to memory corruption
    (bsc#1097599).

  - CVE-2018-17229: Fixed a heap based buffer overflow in
    Exiv2::d2Data via a crafted image (bsc#1109175).

  - CVE-2018-17230: Fixed a heap based buffer overflow in
    Exiv2::d2Data via a crafted image (bsc#1109176).

  - CVE-2018-17282: Fixed a NULL pointer dereference in
    Exiv2::DataValue::copy (bsc#1109299).

  - CVE-2018-19108: Fixed an integer overflow in
    Exiv2::PsdImage::readMetadata which could have led to
    infinite loop (bsc#1115364).

  - CVE-2018-19607: Fixed a NULL pointer dereference in
    Exiv2::isoSpeed which might have led to denial of
    service (bsc#1117513).

  - CVE-2018-9305: Fixed an out of bounds read in
    IptcData::printStructure which might have led to to
    information leak or denial of service (bsc#1088424).

  - CVE-2019-13114: Fixed a NULL pointer dereference which
    might have led to denial of service via a crafted
    response of an malicious http server (bsc#1142684).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142684"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected exiv2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exiv2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exiv2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exiv2-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexiv2-26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexiv2-26-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexiv2-26-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexiv2-26-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexiv2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"exiv2-0.26-lp151.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"exiv2-debuginfo-0.26-lp151.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"exiv2-debugsource-0.26-lp151.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"exiv2-lang-0.26-lp151.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libexiv2-26-0.26-lp151.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libexiv2-26-debuginfo-0.26-lp151.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libexiv2-devel-0.26-lp151.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libexiv2-26-32bit-0.26-lp151.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libexiv2-26-32bit-debuginfo-0.26-lp151.7.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exiv2 / exiv2-debuginfo / exiv2-debugsource / exiv2-lang / etc");
}
