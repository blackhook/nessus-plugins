#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-727.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111098);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-11337", "CVE-2017-11338", "CVE-2017-11339", "CVE-2017-11340", "CVE-2017-11553", "CVE-2017-11591", "CVE-2017-11592", "CVE-2017-11683", "CVE-2017-12955", "CVE-2017-12956", "CVE-2017-12957", "CVE-2017-14859", "CVE-2017-14860", "CVE-2017-14862", "CVE-2017-14864");

  script_name(english:"openSUSE Security Update : exiv2 (openSUSE-2018-727)");
  script_summary(english:"Check for the openSUSE-2018-727 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for exiv2 to 0.26 fixes the following security issues :

  - CVE-2017-14864: Prevent invalid memory address
    dereference in Exiv2::getULong that could have caused a
    segmentation fault and application crash, which leads to
    denial of service (bsc#1060995).

  - CVE-2017-14862: Prevent invalid memory address
    dereference in Exiv2::DataValue::read that could have
    caused a segmentation fault and application crash, which
    leads to denial of service (bsc#1060996).

  - CVE-2017-14859: Prevent invalid memory address
    dereference in Exiv2::StringValueBase::read that could
    have caused a segmentation fault and application crash,
    which leads to denial of service (bsc#1061000).

  - CVE-2017-14860: Prevent heap-based buffer over-read in
    the Exiv2::Jp2Image::readMetadata function via a crafted
    input that could have lead to a denial of service attack
    (bsc#1061023).

  - CVE-2017-11337: Prevent invalid free in the
    Action::TaskFactory::cleanup function via a crafted
    input that could have lead to a remote denial of service
    attack (bsc#1048883).

  - CVE-2017-11338: Prevent infinite loop in the
    Exiv2::Image::printIFDStructure function via a crafted
    input that could have lead to a remote denial of service
    attack (bsc#1048883).

  - CVE-2017-11339: Prevent heap-based buffer overflow in
    the Image::printIFDStructure function via a crafted
    input that could have lead to a remote denial of service
    attack (bsc#1048883).

  - CVE-2017-11340: Prevent Segmentation fault in the
    XmpParser::terminate() function via a crafted input that
    could have lead to a remote denial of service attack
    (bsc#1048883).

  - CVE-2017-12955: Prevent heap-based buffer overflow. The
    vulnerability caused an out-of-bounds write in
    Exiv2::Image::printIFDStructure(), which may lead to
    remote denial of service or possibly unspecified other
    impact (bsc#1054593).

  - CVE-2017-12956: Preventn illegal address access in
    Exiv2::FileIo::path[abi:cxx11]() that could have lead to
    remote denial of service (bsc#1054592).

  - CVE-2017-12957: Prevent heap-based buffer over-read that
    was triggered in the Exiv2::Image::io function and could
    have lead to remote denial of service (bsc#1054590).

  - CVE-2017-11683: Prevent reachable assertion in the
    Internal::TiffReader::visitDirectory function that could
    have lead to a remote denial of service attack via
    crafted input (bsc#1051188).

  - CVE-2017-11591: Prevent Floating point exception in the
    Exiv2::ValueType function that could have lead to a
    remote denial of service attack via crafted input
    (bsc#1050257).

  - CVE-2017-11553: Prevent illegal address access in the
    extend_alias_table function via a crafted input could
    have lead to remote denial of service.

  - CVE-2017-11592: Prevent mismatched Memory Management
    Routines vulnerability in the Exiv2::FileIo::seek
    function that could have lead to a remote denial of
    service attack (heap memory corruption) via crafted
    input.

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061023"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected exiv2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/16");
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

if ( rpm_check(release:"SUSE15.0", reference:"exiv2-0.26-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"exiv2-debuginfo-0.26-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"exiv2-debugsource-0.26-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"exiv2-lang-0.26-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libexiv2-26-0.26-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libexiv2-26-debuginfo-0.26-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libexiv2-devel-0.26-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libexiv2-26-32bit-0.26-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libexiv2-26-32bit-debuginfo-0.26-lp150.5.3.1") ) flag++;

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
