#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1039.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117687);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-11440", "CVE-2018-11577", "CVE-2018-11683", "CVE-2018-11684", "CVE-2018-11685", "CVE-2018-12085");

  script_name(english:"openSUSE Security Update : liblouis (openSUSE-2018-1039)");
  script_summary(english:"Check for the openSUSE-2018-1039 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for liblouis fixes the following issues :

Security issues fixed :

  - CVE-2018-11440: Fixed a stack-based buffer overflow in
    the function parseChars() in compileTranslationTable.c
    (bsc#1095189)

  - CVE-2018-11577: Fixed a segmentation fault in
    lou_logPrint in logging.c (bsc#1095945)

  - CVE-2018-11683: Fixed a stack-based buffer overflow in
    the function parseChars() in compileTranslationTable.c
    (different vulnerability than CVE-2018-11440)
    (bsc#1095827)

  - CVE-2018-11684: Fixed stack-based buffer overflow in the
    function includeFile() in compileTranslationTable.c
    (bsc#1095826)

  - CVE-2018-11685: Fixed a stack-based buffer overflow in
    the function compileHyphenation() in
    compileTranslationTable.c (bsc#1095825)

  - CVE-2018-12085: Fixed a stack-based buffer overflow in
    the function parseChars() in compileTranslationTable.c
    (different vulnerability than CVE-2018-11440)
    (bsc#1097103)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097103"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected liblouis packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-louis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/25");
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

if ( rpm_check(release:"SUSE42.3", reference:"liblouis-data-2.6.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"liblouis-debugsource-2.6.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"liblouis-devel-2.6.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"liblouis-tools-2.6.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"liblouis-tools-debuginfo-2.6.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"liblouis9-2.6.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"liblouis9-debuginfo-2.6.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-louis-2.6.4-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "liblouis-data / liblouis-debugsource / liblouis-devel / etc");
}
