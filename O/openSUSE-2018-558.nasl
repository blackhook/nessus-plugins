#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-558.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110336);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-1059");

  script_name(english:"openSUSE Security Update : dpdk-thunderxdpdk (openSUSE-2018-558)");
  script_summary(english:"Check for the openSUSE-2018-558 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following issues :

  - CVE-2018-1059: The DPDK vhost-user interface did not
    check to verify that all the requested guest physical
    range was mapped and contiguous when performing Guest
    Physical Addresses to Host Virtual Addresses
    translations. This may have lead to a malicious guest
    exposing vhost-user backend process memory
    (bsc#1089638). This update was imported from the
    SUSE:SLE-12-SP3:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089638"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dpdk-thunderxdpdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-examples-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/06");
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

if ( rpm_check(release:"SUSE42.3", reference:"dpdk-16.11.6-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dpdk-debuginfo-16.11.6-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dpdk-debugsource-16.11.6-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dpdk-devel-16.11.6-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dpdk-devel-debuginfo-16.11.6-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dpdk-examples-16.11.6-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dpdk-examples-debuginfo-16.11.6-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dpdk-tools-16.11.6-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"dpdk-kmp-default-16.11.6_k4.4.132_53-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"dpdk-kmp-default-debuginfo-16.11.6_k4.4.132_53-6.5.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dpdk / dpdk-debuginfo / dpdk-debugsource / dpdk-devel / etc");
}
