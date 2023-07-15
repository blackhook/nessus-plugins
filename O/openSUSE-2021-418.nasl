#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-418.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(147846);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/05");

  script_cve_id("CVE-2020-35518");

  script_name(english:"openSUSE Security Update : 389-ds (openSUSE-2021-418)");
  script_summary(english:"Check for the openSUSE-2021-418 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for 389-ds fixes the following issues :

  - 389-ds was updated to version 1.4.3.19 

  - CVE-2020-35518: Fixed an information disclosure during
    the binding of a DN (bsc#1181159).

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181159"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected 389-ds packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35518");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lib389");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvrcore0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvrcore0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/17");
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

if ( rpm_check(release:"SUSE15.2", reference:"389-ds-1.4.3.19~git0.bef0b5bed-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"389-ds-debuginfo-1.4.3.19~git0.bef0b5bed-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"389-ds-debugsource-1.4.3.19~git0.bef0b5bed-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"389-ds-devel-1.4.3.19~git0.bef0b5bed-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"389-ds-snmp-1.4.3.19~git0.bef0b5bed-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"389-ds-snmp-debuginfo-1.4.3.19~git0.bef0b5bed-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"lib389-1.4.3.19~git0.bef0b5bed-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libsvrcore0-1.4.3.19~git0.bef0b5bed-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libsvrcore0-debuginfo-1.4.3.19~git0.bef0b5bed-lp152.2.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds / 389-ds-debuginfo / 389-ds-debugsource / 389-ds-devel / etc");
}
