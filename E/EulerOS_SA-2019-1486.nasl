#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124810);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2013-4579",
    "CVE-2013-6367",
    "CVE-2014-1446",
    "CVE-2014-3145",
    "CVE-2014-3610",
    "CVE-2014-3940",
    "CVE-2014-5472",
    "CVE-2015-0573",
    "CVE-2015-1573",
    "CVE-2015-8963",
    "CVE-2016-2117",
    "CVE-2016-2186",
    "CVE-2016-6197",
    "CVE-2017-2636",
    "CVE-2017-6347",
    "CVE-2017-7495",
    "CVE-2018-12232",
    "CVE-2018-14614",
    "CVE-2018-14633",
    "CVE-2018-16882"
  );
  script_bugtraq_id(
    63743,
    64270,
    64954,
    67321,
    67786,
    69428,
    70742,
    72552
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1486)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - It was found that the parse_rock_ridge_inode_internal()
    function of the Linux kernel's ISOFS implementation did
    not correctly check relocated directories when
    processing Rock Ridge child link (CL) tags. An attacker
    with physical access to the system could use a
    specially crafted ISO image to crash the system or,
    potentially, escalate their privileges on the
    system.(CVE-2014-5472i1/4%0

  - An issue was discovered in the Linux kernel's F2FS
    filesystem code. An out-of-bounds access vulnerability
    is possible the in __remove_dirty_segment() in
    fs/f2fs/segment.c function when mounting a crafted f2fs
    image.(CVE-2018-14614i1/4%0

  - Race condition in kernel/events/core.c in the Linux
    kernel before 4.4 allows local users to gain privileges
    or cause a denial of service via use-after-free
    vulnerability by leveraging incorrect handling of an
    swevent data structure during a CPU unplug
    operation.(CVE-2015-8963i1/4%0

  - The skbs processed by ip_cmsg_recv() are not guaranteed
    to be linear (e.g. when sending UDP packets over
    loopback with MSGMORE). Using csum_partial() on
    potentially the whole skb len is dangerous instead be
    on the safe side and use skb_checksum(). This may lead
    to an infoleak as the kernel memory may be checksummed
    and sent as part of the packet.(CVE-2017-6347i1/4%0

  - The apic_get_tmcct function in arch/x86/kvm/lapic.c in
    the KVM subsystem in the Linux kernel through 3.12.5
    allows guest OS users to cause a denial of service
    (divide-by-zero error and host OS crash) via crafted
    modifications of the TMICT value.(CVE-2013-6367i1/4%0

  - A use-after-free issue was found in the way the Linux
    kernel's KVM hypervisor processed posted interrupts
    when nested(=1) virtualization is enabled. In
    nested_get_vmcs12_pages(), in case of an error while
    processing posted interrupt address, it unmaps the
    'pi_desc_page' without resetting 'pi_desc' descriptor
    address, which is later used in pi_test_and_clear_on().
    A guest user/process could use this flaw to crash the
    host kernel resulting in DoS or potentially gain
    privileged access to a system.(CVE-2018-16882i1/4%0

  - It was discovered that the atl2_probe() function in the
    Atheros L2 Ethernet driver in the Linux kernel
    incorrectly enabled scatter/gather I/O. A remote
    attacker could use this flaw to obtain potentially
    sensitive information from the kernel
    memory.(CVE-2016-2117i1/4%0

  - A flaw was found in the way the nft_flush_table()
    function of the Linux kernel's netfilter tables
    implementation flushed rules that were referencing
    deleted chains. A local user who has the CAP_NET_ADMIN
    capability could use this flaw to crash the
    system.(CVE-2015-1573i1/4%0

  - The powermate_probe function in
    drivers/input/misc/powermate.c in the Linux kernel
    before 4.5.1 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a crafted endpoints value in a USB
    device descriptor.(CVE-2016-2186i1/4%0

  - It was found that KVM's Write to Model Specific
    Register (WRMSR) instruction emulation would write
    non-canonical values passed in by the guest to certain
    MSRs in the host's context. A privileged guest user
    could use this flaw to crash the host.(CVE-2014-3610i1/4%0

  - The BPF_S_ANC_NLATTR_NEST extension implementation in
    the sk_run_filter function in net/core/filter.c in the
    Linux kernel through 3.14.3 uses the reverse order in a
    certain subtraction, which allows local users to cause
    a denial of service (over-read and system crash) via
    crafted BPF instructions. NOTE: the affected code was
    moved to the __skb_get_nlattr_nest function before the
    vulnerability was announced.(CVE-2014-3145i1/4%0

  - The yam_ioctl function in drivers/net/hamradio/yam.c in
    the Linux kernel before 3.12.8 does not initialize a
    certain structure member, which allows local users to
    obtain sensitive information from kernel memory by
    leveraging the CAP_NET_ADMIN capability for an
    SIOCYAMGCFG ioctl call.(CVE-2014-1446i1/4%0

  - A race condition flaw was found in the N_HLDC Linux
    kernel driver when accessing n_hdlc.tbuf list that can
    lead to double free. A local, unprivileged user able to
    set the HDLC line discipline on the tty device could
    use this flaw to increase their privileges on the
    system.(CVE-2017-2636i1/4%0

  - A flaw was found in the way Linux kernel's Transparent
    Huge Pages (THP) implementation handled non-huge page
    migration. A local, unprivileged user could use this
    flaw to crash the kernel by migrating transparent
    hugepages.(CVE-2014-3940i1/4%0

  - A security flaw was found in the
    chap_server_compute_md5() function in the ISCSI target
    code in the Linux kernel in a way an authentication
    request from an ISCSI initiator is processed. An
    unauthenticated remote attacker can cause a stack
    buffer overflow and smash up to 17 bytes of the stack.
    The attack requires the iSCSI target to be enabled on
    the victim host. Depending on how the target's code was
    built (i.e. depending on a compiler, compile flags and
    hardware architecture) an attack may lead to a system
    crash and thus to a denial of service or possibly to a
    non-authorized access to data exported by an iSCSI
    target. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is highly unlikely.(CVE-2018-14633i1/4%0

  - A vulnerability was found in the Linux kernel where
    filesystems mounted with data=ordered mode may allow an
    attacker to read stale data from recently allocated
    blocks in new files after a system 'reset' by abusing
    ext4 mechanics of delayed allocation.(CVE-2017-7495i1/4%0

  - drivers/media/platform/msm/broadcast/tsc.c in the TSC
    driver for the Linux kernel 3.x, as used in Qualcomm
    Innovation Center (QuIC) Android contributions for MSM
    devices and other products, allows attackers to cause a
    denial of service (invalid pointer dereference) or
    possibly have unspecified other impact via a crafted
    application that makes a TSC_GET_CARD_STATUS ioctl
    call.(CVE-2015-0573i1/4%0

  - It was found that the unlink and rename functionality
    in overlayfs did not verify the upper dentry for
    staleness. A local, unprivileged user could use the
    rename syscall on overlayfs on top of xfs to panic or
    crash the system.(CVE-2016-6197i1/4%0

  - In net/socket.c in the Linux kernel through 4.17.1,
    there is a race condition between fchownat and close in
    cases where they target the same socket file
    descriptor, related to the sock_close and
    sockfs_setattr functions. fchownat does not increment
    the file descriptor reference count, which allows close
    to set the socket to NULL during fchownat's execution,
    leading to a NULL pointer dereference and system
    crash.(CVE-2018-12232i1/4%0

  - The ath9k_htc_set_bssid_mask function in
    drivers/net/wireless/ath/ath9k/htc_drv_main.c in the
    Linux kernel through 3.12 uses a BSSID masking approach
    to determine the set of MAC addresses on which a Wi-Fi
    device is listening, which allows remote attackers to
    discover the original MAC address after spoofing by
    sending a series of packets to MAC addresses with
    certain bit manipulations.(CVE-2013-4579i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1486
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7ea14f2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14633");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-0573");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.28-1.2.117",
        "kernel-devel-4.19.28-1.2.117",
        "kernel-headers-4.19.28-1.2.117",
        "kernel-tools-4.19.28-1.2.117",
        "kernel-tools-libs-4.19.28-1.2.117",
        "kernel-tools-libs-devel-4.19.28-1.2.117",
        "perf-4.19.28-1.2.117",
        "python-perf-4.19.28-1.2.117"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
