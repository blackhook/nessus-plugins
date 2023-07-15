#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-66.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121290);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5852", "CVE-2017-5853", "CVE-2017-5854", "CVE-2017-5855", "CVE-2017-5886", "CVE-2017-6840", "CVE-2017-6844", "CVE-2017-6845", "CVE-2017-6847", "CVE-2017-7378", "CVE-2017-7379", "CVE-2017-7380", "CVE-2017-7994", "CVE-2017-8054", "CVE-2017-8787", "CVE-2018-5295", "CVE-2018-5296", "CVE-2018-5308", "CVE-2018-5309", "CVE-2018-8001");

  script_name(english:"openSUSE Security Update : podofo (openSUSE-2019-66)");
  script_summary(english:"Check for the openSUSE-2019-66 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for podofo version 0.9.6 fixes the following issues :

Security issues fixed :

  - CVE-2017-5852: Fix a infinite loop in
    PoDoFo::PdfPage::GetInheritedKeyFromObject (PdfPage.cpp)
    (boo#1023067)

  - CVE-2017-5854: Fix a NULL pointer dereference in
    PdfOutputStream.cpp (boo#1023070)

  - CVE-2017-5886: Fix a heap-based buffer overflow in
    PoDoFo::PdfTokenizer::GetNextToken (PdfTokenizer.cpp)
    (boo#1023380)

  - CVE-2017-6844: Fix a buffer overflow in
    PoDoFo::PdfParser::ReadXRefSubsection (PdfParser.cpp)
    (boo#1027782)

  - CVE-2017-6847: Fix a NULL pointer dereference in
    PoDoFo::PdfVariant::DelayedLoad (PdfVariant.h)
    (boo#1027778)

  - CVE-2017-7379: Fix a heap-based buffer overflow in
    PoDoFo::PdfSimpleEncoding::ConvertToEncoding
    (PdfEncoding.cpp) (boo#1032018)

  - CVE-2018-5296: Fix a denial of service in the
    ReadXRefSubsection function (boo#1075021)

  - CVE-2018-5309: Fix a integer overflow in the
    ReadObjectsFromStream function (boo#1075322)

  - CVE-2017-5853: Fix a signed integer overflow in
    PdfParser.cpp (boo#1023069)

  - CVE-2017-5855: Fix a NULL pointer dereference in the
    ReadXRefSubsection function (boo#1023071)

  - CVE-2017-6840: Fix a invalid memory read in the
    GetColorFromStack function (boo#1027787)

  - CVE-2017-6845: Fix a NULL pointer dereference in the
    SetNonStrokingColorSpace function (boo#1027779)

  - CVE-2017-7378: Fix a heap-based buffer overflow in the
    ExpandTabs function (boo#1032017)

  - CVE-2017-7380: Fix four NULL pointer dereferences
    (boo#1032019)

  - CVE-2017-8054: Fix a denial of service in the
    GetPageNodeFromArray function (boo#1035596)

  - CVE-2018-5295: Fix a integer overflow in the ParseStream
    function (boo#1075026)

  - CVE-2018-5308: Fix undefined behavior in the
    PdfMemoryOutputStream::Write function (boo#1075772)

  - CVE-2018-8001: Fix a heap overflow read vulnerability in
    the UnescapeName function (boo#1084894)

  - CVE-2017-7994, CVE-2017-8787: Fix a denial of service
    via a crafted PDF document (boo#1035534, boo#1037739)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084894"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected podofo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8001");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpodofo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpodofo0_9_6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpodofo0_9_6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:podofo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:podofo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:podofo-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"libpodofo-devel-0.9.6-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpodofo0_9_6-0.9.6-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpodofo0_9_6-debuginfo-0.9.6-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"podofo-0.9.6-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"podofo-debuginfo-0.9.6-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"podofo-debugsource-0.9.6-10.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpodofo-devel / libpodofo0_9_6 / libpodofo0_9_6-debuginfo / etc");
}
