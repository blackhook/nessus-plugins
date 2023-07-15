#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1180.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104084);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-11591", "CVE-2017-11683", "CVE-2017-14859", "CVE-2017-14862", "CVE-2017-14865");

  script_name(english:"openSUSE Security Update : exiv2 (openSUSE-2017-1180)");
  script_summary(english:"Check for the openSUSE-2017-1180 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for exiv2 fixes the following issues :

Security issues fixed :

  - CVE-2017-11591: There is a Floating point exception in
    the Exiv2::ValueType function in Exiv2 0.26 that will
    lead to a remote denial of service attack via crafted
    input. (boo#1050257)

  - CVE-2017-11683: There is a reachable assertion in the
    Internal::TiffReader::visitDirectory function in
    tiffvisitor.cpp of Exiv2 0.26 that will lead to a remote
    denial of service attack via crafted input.
    (boo#1051188)

  - CVE-2017-14865: There is a heap-based buffer overflow in
    the Exiv2::us2Data function of types.cpp in Exiv2 0.26.
    A Crafted input will lead to a denial of service attack.
    (boo#1061003)

  - CVE-2017-14862: An Invalid memory address dereference
    was discovered in Exiv2::DataValue::read in value.cpp in
    Exiv2 0.26. The vulnerability causes a segmentation
    fault and application crash, which leads to denial of
    service. (boo#1060996)

  - CVE-2017-14859: An Invalid memory address dereference
    was discovered in Exiv2::StringValueBase::read in
    value.cpp in Exiv2 0.26. The vulnerability causes a
    segmentation fault and application crash, which leads to
    denial of service. (boo#1061000)"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061003"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected exiv2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exiv2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exiv2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exiv2-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexiv2-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexiv2-14-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexiv2-14-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexiv2-14-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexiv2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/23");
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

if ( rpm_check(release:"SUSE42.2", reference:"exiv2-0.25-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"exiv2-debuginfo-0.25-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"exiv2-debugsource-0.25-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"exiv2-lang-0.25-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libexiv2-14-0.25-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libexiv2-14-debuginfo-0.25-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libexiv2-devel-0.25-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libexiv2-14-32bit-0.25-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libexiv2-14-debuginfo-32bit-0.25-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"exiv2-0.25-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"exiv2-debuginfo-0.25-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"exiv2-debugsource-0.25-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"exiv2-lang-0.25-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libexiv2-14-0.25-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libexiv2-14-debuginfo-0.25-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libexiv2-devel-0.25-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libexiv2-14-32bit-0.25-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libexiv2-14-debuginfo-32bit-0.25-10.1") ) flag++;

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
