#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-507.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(135451);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/15");

  script_cve_id("CVE-2020-1747");
  script_xref(name:"IAVA", value:"2021-A-0463");

  script_name(english:"openSUSE Security Update : python-PyYAML (openSUSE-2020-507)");
  script_summary(english:"Check for the openSUSE-2020-507 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for python-PyYAML fixes the following issues :

  - CVE-2020-1747: Fixed an arbitrary code execution when
    YAML files are parsed by FullLoader (bsc#1165439).

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165439"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-PyYAML packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-PyYAML-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-PyYAML-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-PyYAML");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-PyYAML-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-PyYAML");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-PyYAML-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"python-PyYAML-debuginfo-5.1.2-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-PyYAML-debugsource-5.1.2-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python2-PyYAML-5.1.2-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python2-PyYAML-debuginfo-5.1.2-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-PyYAML-5.1.2-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-PyYAML-debuginfo-5.1.2-lp151.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-PyYAML-debuginfo / python-PyYAML-debugsource / etc");
}
