#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-734.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101134);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000364");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-734) (Stack Clash)");
  script_summary(english:"Check for the openSUSE-2017-734 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.2 kernel was updated to 4.4.73 to receive
security and bugfixes.

The following security bugs were fixed :

  - CVE-2017-1000364: An issue was discovered in the size of
    the stack guard page on Linux, specifically a 4k stack
    guard page is not sufficiently large and can be 'jumped'
    over (the stack guard page is bypassed), this affects
    Linux Kernel versions 4.11.5 and earlier (the stackguard
    page was introduced in 2010) (bnc#1039348).

    The previous fix caused some Java applications to crash
    and has been replaced by the upstream fix.

The following non-security bugs were fixed :

  - md: fix a null dereference (bsc#1040351).

  - net/mlx5e: Fix timestamping capabilities reporting
    (bsc#966170, bsc#1015342)

  - reiserfs: don't preallocate blocks for extended
    attributes (bsc#990682)

  - ibmvnic: Fix error handling when registering
    long-term-mapped buffers (bsc#1045568).

  - Fix kabi after adding new field to struct mddev
    (bsc#1040351).

  - Fix soft lockup in svc_rdma_send (bsc#729329).

  - IB/addr: Fix setting source address in addr6_resolve()
    (bsc#1044082).

  - IB/ipoib: Fix memory leak in create child syscall
    (bsc#1022595 FATE#322350).

  - IB/mlx5: Assign DSCP for R-RoCE QPs Address Path
    (bsc#966170 bsc#966172 bsc#966191).

  - IB/mlx5: Check supported flow table size (bsc#966170
    bsc#966172 bsc#966191).

  - IB/mlx5: Enlarge autogroup flow table (bsc#966170
    bsc#966172 bsc#966191).

  - IB/mlx5: Fix kernel to user leak prevention logic
    (bsc#966170 bsc#966172 bsc#966191).

  - NFSv4: do not let hanging mounts block other mounts
    (bsc#1040364).

  - [v2, 2/3] powerpc/fadump: avoid holes in boot memory
    area when fadump is registered (bsc#1037669).

  - [v2,1/3] powerpc/fadump: avoid duplicates in crash
    memory ranges (bsc#1037669).

  - [v2,3/3] powerpc/fadump: provide a helpful error message
    (bsc#1037669).

  - dm: remove dummy dm_table definition (bsc#1045307)

  - ibmvnic: Activate disabled RX buffer pools on reset
    (bsc#1044767).

  - ibmvnic: Client-initiated failover (bsc#1043990).

  - ibmvnic: Correct return code checking for ibmvnic_init
    during probe (bsc#1045286).

  - ibmvnic: Ensure that TX queues are disabled in
    __ibmvnic_close (bsc#1044767).

  - ibmvnic: Exit polling routine correctly during adapter
    reset (bsc#1044767).

  - ibmvnic: Fix incorrectly defined ibmvnic_request_map_rsp
    structure (bsc#1045568).

  - ibmvnic: Remove VNIC_CLOSING check from pending_scrq
    (bsc#1044767).

  - ibmvnic: Remove module author mailing address
    (bsc#1045467).

  - ibmvnic: Remove netdev notify for failover resets
    (bsc#1044120).

  - ibmvnic: Return from ibmvnic_resume if not in VNIC_OPEN
    state (bsc#1045235).

  - ibmvnic: Sanitize entire SCRQ buffer on reset
    (bsc#1044767).

  - ibmvnic: driver initialization for kdump/kexec
    (bsc#1044772).

  - ipv6: release dst on error in ip6_dst_lookup_tail
    (git-fixes).

  - jump label: fix passing kbuild_cflags when checking for
    asm goto support (git-fixes).

  - kabi workaround for net: ipv6: Fix processing of RAs in
    presence of VRF (bsc#1042286).

  - lan78xx: use skb_cow_head() to deal with cloned skbs
    (bsc#1045154).

  - loop: Add PF_LESS_THROTTLE to block/loop device thread
    (bsc#1027101).

  - md: use a separate bio_set for synchronous IO
    (bsc#1040351).

  - mlx4: Fix memory leak after mlx4_en_update_priv()
    (bsc#966170 bsc#966172 bsc#966191).

  - mm: fix new crash in unmapped_area_topdown()
    (bnc#1039348).

  - net/mlx5: Do not unlock fte while still using it
    (bsc#966170 bsc#966172 bsc#966191).

  - net/mlx5: Fix create autogroup prev initializer
    (bsc#966170 bsc#966172 bsc#966191).

  - net/mlx5: Prevent setting multicast macs for VFs
    (bsc#966170 bsc#966172 bsc#966191).

  - net/mlx5: Release FTE lock in error flow (bsc#966170
    bsc#966172 bsc#966191).

  - net/mlx5e: Modify TIRs hash only when it's needed
    (bsc#966170 bsc#966172 bsc#966191).

  - net: icmp_route_lookup should use rt dev to determine L3
    domain (bsc#1042286).

  - net: ipv6: Fix processing of RAs in presence of VRF
    (bsc#1042286).

  - net: l3mdev: Add master device lookup by index
    (bsc#1042286).

  - net: make netdev_for_each_lower_dev safe for device
    removal (bsc#1042286).

  - net: vrf: Create FIB tables on link create
    (bsc#1042286).

  - net: vrf: Fix crash when IPv6 is disabled at boot time
    (bsc#1042286).

  - net: vrf: Fix dev refcnt leak due to IPv6 prefix route
    (bsc#1042286).

  - net: vrf: Fix dst reference counting (bsc#1042286).

  - net: vrf: Switch dst dev to loopback on device delete
    (bsc#1042286).

  - net: vrf: protect changes to private data with rcu
    (bsc#1042286).

  - powerpc/fadump: add reschedule point while releasing
    memory (bsc#1040609).

  - powerpc/fadump: return error when fadump registration
    fails (bsc#1040567).

  - ravb: Fix use-after-free on `ifconfig eth0 down`
    (git-fixes).

  - sctp: check af before verify address in
    sctp_addr_id2transport (git-fixes).

  - vrf: remove slave queue and private slave struct
    (bsc#1042286).

  - xen-blkback: do not leak stack data via response ring
    (bsc#1042863 XSA-216).

  - xfrm: Only add l3mdev oif to dst lookups (bsc#1042286)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990682"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'rsh_stack_clash_priv_esc.rb');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/26");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-debuginfo-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debuginfo-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debugsource-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-debuginfo-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-debuginfo-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debuginfo-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debugsource-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-devel-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-devel-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-html-4.4.73-18.17.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-pdf-4.4.73-18.17.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-macros-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-debugsource-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-qa-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-vanilla-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-syms-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-debuginfo-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debuginfo-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debugsource-4.4.73-18.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-devel-4.4.73-18.17.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-docs-html / kernel-docs-pdf / kernel-devel / kernel-macros / etc");
}
