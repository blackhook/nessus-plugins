#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1011.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102967);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-8146", "CVE-2014-8147");

  script_name(english:"openSUSE Security Update : icu (openSUSE-2017-1011)");
  script_summary(english:"Check for the openSUSE-2017-1011 patch");

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
    text (bsc#929629). This update was imported from the
    SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=929629"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected icu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.2", reference:"icu-52.1-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"icu-data-52.1-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"icu-debuginfo-52.1-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"icu-debugsource-52.1-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libicu-devel-52.1-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libicu52_1-52.1-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libicu52_1-data-52.1-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libicu52_1-debuginfo-52.1-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libicu-devel-32bit-52.1-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libicu52_1-32bit-52.1-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libicu52_1-debuginfo-32bit-52.1-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icu-52.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icu-data-52.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icu-debuginfo-52.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icu-debugsource-52.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libicu-devel-52.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libicu52_1-52.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libicu52_1-data-52.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libicu52_1-debuginfo-52.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libicu-devel-32bit-52.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libicu52_1-32bit-52.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libicu52_1-debuginfo-32bit-52.1-15.1") ) flag++;

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
