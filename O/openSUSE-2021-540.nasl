#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-540.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(148432);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/12");

  script_name(english:"openSUSE Security Update : openSUSE KMPs (openSUSE-2021-540)");
  script_summary(english:"Check for the openSUSE-2021-540 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for various openSUSE kernel related packages refreshes
them with the new UEFI Secure boot key."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174543"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected openSUSE KMPs packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-preempt-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-examples-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdpdk-20_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdpdk-20_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:msr-safe-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:msr-safe-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:msr-safe-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:msr-safe-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:msr-safe-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-authlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-authlibs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-authlibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-fuse_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-fuse_client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtl8812au");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtl8812au-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtl8812au-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtl8812au-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtl8812au-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtl8812au-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:system-user-msr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:system-user-msr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-autoload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/12");
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

if ( rpm_check(release:"SUSE15.2", reference:"bbswitch-0.8-lp152.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bbswitch-debugsource-0.8-lp152.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bbswitch-kmp-default-0.8_k5.3.18_lp152.69-lp152.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bbswitch-kmp-default-debuginfo-0.8_k5.3.18_lp152.69-lp152.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bbswitch-kmp-preempt-0.8_k5.3.18_lp152.69-lp152.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bbswitch-kmp-preempt-debuginfo-0.8_k5.3.18_lp152.69-lp152.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-7.2.8-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-debuginfo-7.2.8-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-debugsource-7.2.8-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-devel-7.2.8-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-eppic-7.2.8-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-eppic-debuginfo-7.2.8-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-gcore-7.2.8-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-gcore-debuginfo-7.2.8-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-kmp-default-7.2.8_k5.3.18_lp152.69-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-kmp-default-debuginfo-7.2.8_k5.3.18_lp152.69-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-kmp-preempt-7.2.8_k5.3.18_lp152.69-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-kmp-preempt-debuginfo-7.2.8_k5.3.18_lp152.69-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-19.11.4-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-debuginfo-19.11.4-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-debugsource-19.11.4-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-devel-19.11.4-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-devel-debuginfo-19.11.4-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-examples-19.11.4-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-examples-debuginfo-19.11.4-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-kmp-default-19.11.4_k5.3.18_lp152.69-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-kmp-default-debuginfo-19.11.4_k5.3.18_lp152.69-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-kmp-preempt-19.11.4_k5.3.18_lp152.69-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-kmp-preempt-debuginfo-19.11.4_k5.3.18_lp152.69-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-tools-19.11.4-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-tools-debuginfo-19.11.4-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"drbd-9.0.22~1+git.fe2b5983-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"drbd-debugsource-9.0.22~1+git.fe2b5983-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"drbd-kmp-default-9.0.22~1+git.fe2b5983_k5.3.18_lp152.69-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"drbd-kmp-default-debuginfo-9.0.22~1+git.fe2b5983_k5.3.18_lp152.69-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"drbd-kmp-preempt-9.0.22~1+git.fe2b5983_k5.3.18_lp152.69-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"drbd-kmp-preempt-debuginfo-9.0.22~1+git.fe2b5983_k5.3.18_lp152.69-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libdpdk-20_0-19.11.4-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libdpdk-20_0-debuginfo-19.11.4-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mhvtl-1.62-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mhvtl-debuginfo-1.62-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mhvtl-debugsource-1.62-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mhvtl-kmp-default-1.62_k5.3.18_lp152.69-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mhvtl-kmp-default-debuginfo-1.62_k5.3.18_lp152.69-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mhvtl-kmp-preempt-1.62_k5.3.18_lp152.69-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mhvtl-kmp-preempt-debuginfo-1.62_k5.3.18_lp152.69-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"msr-safe-debugsource-1.4.0-lp152.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"msr-safe-kmp-default-1.4.0_k5.3.18_lp152.69-lp152.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"msr-safe-kmp-default-debuginfo-1.4.0_k5.3.18_lp152.69-lp152.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"msr-safe-kmp-preempt-1.4.0_k5.3.18_lp152.69-lp152.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"msr-safe-kmp-preempt-debuginfo-1.4.0_k5.3.18_lp152.69-lp152.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-1.8.7-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-authlibs-1.8.7-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-authlibs-debuginfo-1.8.7-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-authlibs-devel-1.8.7-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-client-1.8.7-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-client-debuginfo-1.8.7-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-debuginfo-1.8.7-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-debugsource-1.8.7-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-devel-1.8.7-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-devel-debuginfo-1.8.7-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-fuse_client-1.8.7-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-fuse_client-debuginfo-1.8.7-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-kernel-source-1.8.7-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-kmp-default-1.8.7_k5.3.18_lp152.69-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-kmp-default-debuginfo-1.8.7_k5.3.18_lp152.69-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-kmp-preempt-1.8.7_k5.3.18_lp152.69-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-kmp-preempt-debuginfo-1.8.7_k5.3.18_lp152.69-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-server-1.8.7-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-server-debuginfo-1.8.7-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcfclock-0.44-lp152.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcfclock-debuginfo-0.44-lp152.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcfclock-debugsource-0.44-lp152.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcfclock-kmp-default-0.44_k5.3.18_lp152.69-lp152.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcfclock-kmp-default-debuginfo-0.44_k5.3.18_lp152.69-lp152.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcfclock-kmp-preempt-0.44_k5.3.18_lp152.69-lp152.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcfclock-kmp-preempt-debuginfo-0.44_k5.3.18_lp152.69-lp152.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-virtualbox-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-virtualbox-debuginfo-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rtl8812au-5.6.4.2+git20200318.49e98ff-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rtl8812au-debugsource-5.6.4.2+git20200318.49e98ff-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rtl8812au-kmp-default-5.6.4.2+git20200318.49e98ff_k5.3.18_lp152.69-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rtl8812au-kmp-default-debuginfo-5.6.4.2+git20200318.49e98ff_k5.3.18_lp152.69-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rtl8812au-kmp-preempt-5.6.4.2+git20200318.49e98ff_k5.3.18_lp152.69-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rtl8812au-kmp-preempt-debuginfo-5.6.4.2+git20200318.49e98ff_k5.3.18_lp152.69-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sysdig-0.26.5-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sysdig-debuginfo-0.26.5-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sysdig-debugsource-0.26.5-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sysdig-kmp-default-0.26.5_k5.3.18_lp152.69-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sysdig-kmp-default-debuginfo-0.26.5_k5.3.18_lp152.69-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sysdig-kmp-preempt-0.26.5_k5.3.18_lp152.69-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sysdig-kmp-preempt-debuginfo-0.26.5_k5.3.18_lp152.69-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"system-user-msr-1.4.0-lp152.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"system-user-msr-debuginfo-1.4.0-lp152.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"v4l2loopback-autoload-0.12.5-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"v4l2loopback-debugsource-0.12.5-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"v4l2loopback-kmp-default-0.12.5_k5.3.18_lp152.69-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"v4l2loopback-kmp-default-debuginfo-0.12.5_k5.3.18_lp152.69-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"v4l2loopback-kmp-preempt-0.12.5_k5.3.18_lp152.69-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"v4l2loopback-kmp-preempt-debuginfo-0.12.5_k5.3.18_lp152.69-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"v4l2loopback-utils-0.12.5-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vhba-kmp-default-20200106_k5.3.18_lp152.69-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vhba-kmp-default-debuginfo-20200106_k5.3.18_lp152.69-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vhba-kmp-preempt-20200106_k5.3.18_lp152.69-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vhba-kmp-preempt-debuginfo-20200106_k5.3.18_lp152.69-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-debuginfo-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-debugsource-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-devel-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-desktop-icons-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-source-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-tools-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-tools-debuginfo-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-x11-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-x11-debuginfo-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-host-source-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-debugsource-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-default-6.1.18_k5.3.18_lp152.69-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-default-debuginfo-6.1.18_k5.3.18_lp152.69-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-preempt-6.1.18_k5.3.18_lp152.69-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-preempt-debuginfo-6.1.18_k5.3.18_lp152.69-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-qt-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-qt-debuginfo-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-vnc-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-websrv-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-websrv-debuginfo-6.1.18-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xtables-addons-3.9-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xtables-addons-debuginfo-3.9-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xtables-addons-kmp-default-3.9_k5.3.18_lp152.69-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xtables-addons-kmp-default-debuginfo-3.9_k5.3.18_lp152.69-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xtables-addons-kmp-preempt-3.9_k5.3.18_lp152.69-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xtables-addons-kmp-preempt-debuginfo-3.9_k5.3.18_lp152.69-lp152.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bbswitch / bbswitch-debugsource / bbswitch-kmp-default / etc");
}
