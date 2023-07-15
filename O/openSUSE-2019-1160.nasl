#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1160.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123815);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-11410", "CVE-2018-11440", "CVE-2018-11577", "CVE-2018-11683", "CVE-2018-11684", "CVE-2018-11685", "CVE-2018-12085", "CVE-2018-17294");

  script_name(english:"openSUSE Security Update : liblouis (openSUSE-2019-1160)");
  script_summary(english:"Check for the openSUSE-2019-1160 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for liblouis fixes the following issues :

Security issues fixed :

  - CVE-2018-17294: Fixed an out of bounds read in
    matchCurrentInput function which could allow a remote
    attacker to cause Denail of Service (bsc#1109319).

  - CVE-2018-11410: Fixed an invalid free in the compileRule
    function in compileTranslationTable.c (bsc#1094685)

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

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094685"
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
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109319"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected liblouis packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblouis14-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-louis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/08");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"liblouis-data-3.3.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"liblouis-debuginfo-3.3.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"liblouis-debugsource-3.3.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"liblouis-devel-3.3.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"liblouis-tools-3.3.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"liblouis-tools-debuginfo-3.3.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"liblouis14-3.3.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"liblouis14-debuginfo-3.3.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-louis-3.3.0-lp150.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "liblouis-data / liblouis-debuginfo / liblouis-debugsource / etc");
}
