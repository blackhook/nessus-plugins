#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-788.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149885);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/27");

  script_cve_id("CVE-2021-30145");

  script_name(english:"openSUSE Security Update : mpv (openSUSE-2021-788)");
  script_summary(english:"Check for the openSUSE-2021-788 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for mpv fixes the following issues :

  - CVE-2021-30145: Fixed format string vulnerability allows
    user-assisted remote attackers to achieve code execution
    via a crafted m3u playlist file (boo#1186230)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1186230"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected mpv packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30145");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmpv1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmpv1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpv-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpv-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libmpv1-0.32.0+git.20200301T004003.e7bab0025f-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libmpv1-debuginfo-0.32.0+git.20200301T004003.e7bab0025f-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mpv-0.32.0+git.20200301T004003.e7bab0025f-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mpv-bash-completion-0.32.0+git.20200301T004003.e7bab0025f-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mpv-debuginfo-0.32.0+git.20200301T004003.e7bab0025f-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mpv-debugsource-0.32.0+git.20200301T004003.e7bab0025f-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mpv-devel-0.32.0+git.20200301T004003.e7bab0025f-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mpv-zsh-completion-0.32.0+git.20200301T004003.e7bab0025f-lp152.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmpv1 / libmpv1-debuginfo / mpv / mpv-bash-completion / etc");
}
