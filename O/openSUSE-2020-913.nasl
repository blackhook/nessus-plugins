#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-913.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138719);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/22");

  script_cve_id("CVE-2019-18934", "CVE-2020-12662", "CVE-2020-12663");

  script_name(english:"openSUSE Security Update : unbound (openSUSE-2020-913)");
  script_summary(english:"Check for the openSUSE-2020-913 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for unbound fixes the following issues :

  - CVE-2020-12662: Fixed an issue where unbound could have
    been tricked into amplifying an incoming query into a
    large number of queries directed to a target
    (bsc#1171889).

  - CVE-2020-12663: Fixed an issue where malformed answers
    from upstream name servers could have been used to make
    unbound unresponsive (bsc#1171889).&#9; 

  - CVE-2019-18934: Fixed a vulnerability in the IPSec
    module which could have allowed code execution after
    receiving a special crafted answer (bsc#1157268).

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171889"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected unbound packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18934");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libunbound-devel-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libunbound-devel-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libunbound-devel-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libunbound2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libunbound2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unbound-anchor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unbound-anchor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unbound-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unbound-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unbound-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unbound-munin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unbound-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unbound-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
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

if ( rpm_check(release:"SUSE15.2", reference:"libunbound-devel-mini-1.6.8-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libunbound-devel-mini-debuginfo-1.6.8-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libunbound-devel-mini-debugsource-1.6.8-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"unbound-munin-1.6.8-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libunbound2-1.6.8-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libunbound2-debuginfo-1.6.8-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"unbound-1.6.8-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"unbound-anchor-1.6.8-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"unbound-anchor-debuginfo-1.6.8-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"unbound-debuginfo-1.6.8-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"unbound-debugsource-1.6.8-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"unbound-devel-1.6.8-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"unbound-python-1.6.8-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"unbound-python-debuginfo-1.6.8-lp152.9.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libunbound-devel-mini / libunbound-devel-mini-debuginfo / etc");
}
