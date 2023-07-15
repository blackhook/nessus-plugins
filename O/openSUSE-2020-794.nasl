#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-794.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(138676);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2019-20807");
  script_xref(name:"IAVB", value:"2020-B-0053-S");

  script_name(english:"openSUSE Security Update : vim (openSUSE-2020-794)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for vim fixes the following issues :

  - CVE-2019-20807: Fixed an issue where escaping from the
    restrictive mode of vim was possible using interfaces
    (bsc#1172225). 

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172225");
  script_set_attribute(attribute:"solution", value:
"Update the affected vim packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20807");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-data-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"gvim-8.0.1568-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gvim-debuginfo-8.0.1568-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vim-8.0.1568-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vim-data-8.0.1568-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vim-data-common-8.0.1568-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vim-debuginfo-8.0.1568-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vim-debugsource-8.0.1568-lp151.5.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gvim / gvim-debuginfo / vim / vim-data / vim-data-common / etc");
}
