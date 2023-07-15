#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-89.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145366);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/25");

  script_name(english:"openSUSE Security Update : open-iscsi (openSUSE-2021-89)");
  script_summary(english:"Check for the openSUSE-2021-89 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for open-iscsi fixes the following issues :

  - Updated to upstream version 2.1.3 as 2.1.3-suse, for
    bsc#1179908, including :

  - uip: check for TCP urgent pointer past end of frame

  - uip: check for u8 overflow when processing TCP options

  - uip: check for header length underflow during checksum
    calculation

  - fwparam_ppc: Fix memory leak in fwparam_ppc.c

  - iscsiuio: Remove unused macro IFNAMSIZ defined in
    iscsid_ipc.c

  - fwparam_ppc: Fix illegal memory access in fwparam_ppc.c

  - sysfs: Verify parameter of sysfs_device_get()

  - fwparam_ppc: Fix NULL pointer dereference in
    find_devtree()

  - open-iscsi: Clean user_param list when process exit

  - iscsi_net_util: Fix NULL pointer dereference in
    find_vlan_dev()

  - open-iscsi: Fix NULL pointer dereference in
    mgmt_ipc_read_req()

  - open-iscsi: Fix invalid pointer deference in
    find_initiator()

  - iscsiuio: Fix invalid parameter when call fstat()

  - iscsi-iname: Verify open() return value before calling
    read()

  - iscsi_sysfs: Fix NULL pointer deference in
    iscsi_sysfs_read_iface

  - Updatged to latest upstream, including :

  - iscsiadm: Optimize the the verification of mode
    paramters

  - iscsid: Poll timeout value to 1 minute for iscsid

  - iscsiadm: fix host stats mode coredump

  - iscsid: fix logging level when starting and shutting
    down daemon

  - Updated iscsiadm man page.

  - Fix memory leak in sysfs_get_str

  - libopeniscsiusr: Compare with max int instead of max
    long

  - Systemd unit files should not depend on network.target
    (bsc#1179440).

  - Updated to latest upstream, including async login
    ability :

  - Implement login 'no_wait' for iscsiadm NODE mode

  - iscsiadm buffer overflow regression when discovering
    many targets at once

  - iscsid: Check Invalid Session id for stop connection

  - Add ability to attempt target logins asynchronously

  - %service_del_postun_without_restart is now available on
    SLE More accurately it's been introduced in SLE12-SP2+
    and SLE15+

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179908"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected open-iscsi packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsiuio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsiuio-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopeniscsiusr0_2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopeniscsiusr0_2_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:open-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:open-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:open-iscsi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:open-iscsi-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"iscsiuio-0.7.8.6-lp152.18.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"iscsiuio-debuginfo-0.7.8.6-lp152.18.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libopeniscsiusr0_2_0-2.1.3-lp152.18.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libopeniscsiusr0_2_0-debuginfo-2.1.3-lp152.18.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"open-iscsi-2.1.3-lp152.18.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"open-iscsi-debuginfo-2.1.3-lp152.18.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"open-iscsi-debugsource-2.1.3-lp152.18.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"open-iscsi-devel-2.1.3-lp152.18.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "iscsiuio / iscsiuio-debuginfo / libopeniscsiusr0_2_0 / etc");
}
