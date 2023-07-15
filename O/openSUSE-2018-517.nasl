#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-517.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110107);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-8146", "CVE-2014-8147", "CVE-2016-6293", "CVE-2017-14952", "CVE-2017-15422", "CVE-2017-17484", "CVE-2017-7867", "CVE-2017-7868");

  script_name(english:"openSUSE Security Update : icu (openSUSE-2018-517)");
  script_summary(english:"Check for the openSUSE-2018-517 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"icu was updated to fix two security issues.

These security issues were fixed :

  - CVE-2014-8147: The resolveImplicitLevels function in
    common/ubidi.c in the Unicode Bidirectional Algorithm
    implementation in ICU4C in International Components for
    Unicode (ICU) used an integer data type that is
    inconsistent with a header file, which allowed remote
    attackers to cause a denial of service (incorrect malloc
    followed by invalid free) or possibly execute arbitrary
    code via crafted text (bsc#929629).

  - CVE-2014-8146: The resolveImplicitLevels function in
    common/ubidi.c in the Unicode Bidirectional Algorithm
    implementation in ICU4C in International Components for
    Unicode (ICU) did not properly track directionally
    isolated pieces of text, which allowed remote attackers
    to cause a denial of service (heap-based buffer
    overflow) or possibly execute arbitrary code via crafted
    text (bsc#929629).

  - CVE-2016-6293: The uloc_acceptLanguageFromHTTP function
    in common/uloc.cpp in International Components for
    Unicode (ICU) for C/C++ did not ensure that there is a
    '\0' character at the end of a certain temporary array,
    which allowed remote attackers to cause a denial of
    service (out-of-bounds read) or possibly have
    unspecified other impact via a call with a long
    httpAcceptLanguage argument (bsc#990636).

  - CVE-2017-7868: International Components for Unicode
    (ICU) for C/C++ 2017-02-13 has an out-of-bounds write
    caused by a heap-based buffer overflow related to the
    utf8TextAccess function in common/utext.cpp and the
    utext_moveIndex32* function (bsc#1034674)

  - CVE-2017-7867: International Components for Unicode
    (ICU) for C/C++ 2017-02-13 has an out-of-bounds write
    caused by a heap-based buffer overflow related to the
    utf8TextAccess function in common/utext.cpp and the
    utext_setNativeIndex* function (bsc#1034678)

  - CVE-2017-14952: Double free in i18n/zonemeta.cpp in
    International Components for Unicode (ICU) for C/C++
    allowed remote attackers to execute arbitrary code via a
    crafted string, aka a 'redundant UVector entry clean up
    function call' issue (bnc#1067203)

  - CVE-2017-17484: The ucnv_UTF8FromUTF8 function in
    ucnv_u8.cpp in International Components for Unicode
    (ICU) for C/C++ mishandled ucnv_convertEx calls for
    UTF-8 to UTF-8 conversion, which allowed remote
    attackers to cause a denial of service (stack-based
    buffer overflow and application crash) or possibly have
    unspecified other impact via a crafted string, as
    demonstrated by ZNC (bnc#1072193)

  - CVE-2017-15422: An integer overflow in icu during
    persian calendar date processing could lead to incorrect
    years shown (bnc#1077999)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=929629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990636"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected icu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icu-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu52_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu52_1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu52_1-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu52_1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu52_1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/25");
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

if ( rpm_check(release:"SUSE42.3", reference:"icu-52.1-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icu-data-52.1-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icu-debuginfo-52.1-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icu-debugsource-52.1-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libicu-devel-52.1-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libicu52_1-52.1-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libicu52_1-data-52.1-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libicu52_1-debuginfo-52.1-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libicu-devel-32bit-52.1-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libicu52_1-32bit-52.1-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libicu52_1-debuginfo-32bit-52.1-18.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icu / icu-data / icu-debuginfo / icu-debugsource / etc");
}
