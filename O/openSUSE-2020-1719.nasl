#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1719.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141884);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/28");

  script_cve_id("CVE-2019-16707");

  script_name(english:"openSUSE Security Update : hunspell (openSUSE-2020-1719)");
  script_summary(english:"Check for the openSUSE-2020-1719 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for hunspell fixes the following issues :

  - CVE-2019-16707: Fixed an invalid read in
    SuggestMgr:leftcommonsubstring (bsc#1151867).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151867"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected hunspell packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhunspell-1_6-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhunspell-1_6-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhunspell-1_6-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhunspell-1_6-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/26");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"hunspell-1.6.2-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"hunspell-debuginfo-1.6.2-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"hunspell-debugsource-1.6.2-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"hunspell-devel-1.6.2-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"hunspell-tools-1.6.2-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"hunspell-tools-debuginfo-1.6.2-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libhunspell-1_6-0-1.6.2-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libhunspell-1_6-0-debuginfo-1.6.2-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"hunspell-devel-32bit-1.6.2-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libhunspell-1_6-0-32bit-1.6.2-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libhunspell-1_6-0-32bit-debuginfo-1.6.2-lp152.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hunspell / hunspell-debuginfo / hunspell-debugsource / etc");
}
