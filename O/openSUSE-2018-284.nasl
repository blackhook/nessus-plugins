#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-284.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108478);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5715");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"openSUSE Security Update : various KMPs (openSUSE-2018-284) (Spectre)");
  script_summary(english:"Check for the openSUSE-2018-284 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Spectre Variant 2 in the Linux Kernel is mitigated using
'retpolines'.

This update rebuilds all openSUSE Leap 42.3 KMPs to use 'retpolines'
and so be able to mitigate the Spectre v2 attack. (bsc#1068032
CVE-2017-5715)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected various KMPs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-eppic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-eppic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-gcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-gcore-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-default-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drm-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ftsteutates-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ftsteutates-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ftsteutates-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ftsteutates-sensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipset3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipset3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if ( rpm_check(release:"SUSE42.3", reference:"crash-7.1.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"crash-debuginfo-7.1.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"crash-debugsource-7.1.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"crash-devel-7.1.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"crash-eppic-7.1.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"crash-eppic-debuginfo-7.1.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"crash-gcore-7.1.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"crash-gcore-debuginfo-7.1.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ftsteutates-sensors-20160601-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"bbswitch-0.8-12.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"bbswitch-debugsource-0.8-12.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"bbswitch-kmp-default-0.8_k4.4.114_42-12.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"bbswitch-kmp-default-debuginfo-0.8_k4.4.114_42-12.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"crash-kmp-default-7.1.8_k4.4.114_42-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"crash-kmp-default-debuginfo-7.1.8_k4.4.114_42-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"dpdk-16.11.1-6.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"dpdk-debuginfo-16.11.1-6.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"dpdk-debugsource-16.11.1-6.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"dpdk-devel-16.11.1-6.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"dpdk-devel-debuginfo-16.11.1-6.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"dpdk-examples-16.11.1-6.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"dpdk-examples-debuginfo-16.11.1-6.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"dpdk-kmp-default-16.11.1_k4.4.114_42-6.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"dpdk-kmp-default-debuginfo-16.11.1_k4.4.114_42-6.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"dpdk-tools-16.11.1-6.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"drbd-9.0.8+git.c8bc3670-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"drbd-debugsource-9.0.8+git.c8bc3670-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"drbd-kmp-default-9.0.8+git.c8bc3670_k4.4.114_42-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"drbd-kmp-default-debuginfo-9.0.8+git.c8bc3670_k4.4.114_42-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"drm-debugsource-4.9.33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"drm-kmp-default-4.9.33_k4.4.114_42-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"drm-kmp-default-debuginfo-4.9.33_k4.4.114_42-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ftsteutates-debugsource-20160601-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ftsteutates-kmp-default-20160601_k4.4.114_42-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ftsteutates-kmp-default-debuginfo-20160601_k4.4.114_42-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"hdjmod-debugsource-1.28-27.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"hdjmod-kmp-default-1.28_k4.4.114_42-27.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"hdjmod-kmp-default-debuginfo-1.28_k4.4.114_42-27.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ipset-6.29-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ipset-debuginfo-6.29-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ipset-debugsource-6.29-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ipset-devel-6.29-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ipset-kmp-default-6.29_k4.4.114_42-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ipset-kmp-default-debuginfo-6.29_k4.4.114_42-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libipset3-6.29-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libipset3-debuginfo-6.29-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ndiswrapper-1.59-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ndiswrapper-debuginfo-1.59-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ndiswrapper-debugsource-1.59-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ndiswrapper-kmp-default-1.59_k4.4.114_42-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ndiswrapper-kmp-default-debuginfo-1.59_k4.4.114_42-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"pcfclock-0.44-272.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"pcfclock-debuginfo-0.44-272.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"pcfclock-debugsource-0.44-272.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"pcfclock-kmp-default-0.44_k4.4.114_42-272.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"pcfclock-kmp-default-debuginfo-0.44_k4.4.114_42-272.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"sysdig-0.17.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"sysdig-debuginfo-0.17.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"sysdig-debugsource-0.17.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"sysdig-kmp-default-0.17.0_k4.4.114_42-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"sysdig-kmp-default-debuginfo-0.17.0_k4.4.114_42-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"vhba-kmp-debugsource-20161009-9.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"vhba-kmp-default-20161009_k4.4.114_42-9.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"vhba-kmp-default-debuginfo-20161009_k4.4.114_42-9.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"xtables-addons-2.11-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"xtables-addons-debuginfo-2.11-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"xtables-addons-debugsource-2.11-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"xtables-addons-kmp-default-2.11_k4.4.114_42-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"xtables-addons-kmp-default-debuginfo-2.11_k4.4.114_42-4.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "crash / crash-debuginfo / crash-debugsource / crash-devel / etc");
}
