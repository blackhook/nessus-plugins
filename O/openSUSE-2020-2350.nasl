#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2350.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145324);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-0487", "CVE-2020-0499");

  script_name(english:"openSUSE Security Update : flac (openSUSE-2020-2350)");
  script_summary(english:"Check for the openSUSE-2020-2350 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for flac fixes the following issues :

  - CVE-2020-0487: Fixed a memory leak (bsc#1180112).

  - CVE-2020-0499: Fixed an out-of-bounds access
    (bsc#1180099).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180112"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected flac packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0499");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flac-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flac-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flac-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libFLAC++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libFLAC++6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libFLAC++6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libFLAC++6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libFLAC8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libFLAC8-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libFLAC8-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libFLAC8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.2", reference:"flac-1.3.2-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"flac-debuginfo-1.3.2-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"flac-debugsource-1.3.2-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"flac-devel-1.3.2-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libFLAC++6-1.3.2-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libFLAC++6-debuginfo-1.3.2-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libFLAC8-1.3.2-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libFLAC8-debuginfo-1.3.2-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"flac-devel-32bit-1.3.2-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libFLAC++6-32bit-1.3.2-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libFLAC++6-32bit-debuginfo-1.3.2-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libFLAC8-32bit-1.3.2-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libFLAC8-32bit-debuginfo-1.3.2-lp152.5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flac / flac-debuginfo / flac-debugsource / flac-devel / libFLAC++6 / etc");
}
