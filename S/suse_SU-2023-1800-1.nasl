#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:1800-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(174049);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id(
    "CVE-2017-5753",
    "CVE-2021-3923",
    "CVE-2022-4744",
    "CVE-2023-0394",
    "CVE-2023-0461",
    "CVE-2023-1075",
    "CVE-2023-1076",
    "CVE-2023-1078",
    "CVE-2023-1095",
    "CVE-2023-1281",
    "CVE-2023-1382",
    "CVE-2023-1390",
    "CVE-2023-1513",
    "CVE-2023-1582",
    "CVE-2023-23004",
    "CVE-2023-25012",
    "CVE-2023-28327",
    "CVE-2023-28328",
    "CVE-2023-28464",
    "CVE-2023-28466",
    "CVE-2023-28772"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:1800-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2023:1800-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2023:1800-1 advisory.

  - Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized
    disclosure of information to an attacker with local user access via a side-channel analysis.
    (CVE-2017-5753)

  - A flaw was found in the Linux kernel's implementation of RDMA over infiniband. An attacker with a
    privileged local account can leak kernel stack information when issuing commands to the
    /dev/infiniband/rdma_cm device node. While this access is unlikely to leak sensitive user information, it
    can be further used to defeat existing kernel protection mechanisms. (CVE-2021-3923)

  - A double-free flaw was found in the Linux kernel's TUN/TAP device driver functionality in how a user
    registers the device when the register_netdevice function fails (NETDEV_REGISTER notifier). This flaw
    allows a local user to crash or potentially escalate their privileges on the system. (CVE-2022-4744)

  - There is a use-after-free vulnerability in the Linux Kernel which can be exploited to achieve local
    privilege escalation. To reach the vulnerability kernel configuration flag CONFIG_TLS or
    CONFIG_XFRM_ESPINTCP has to be configured, but the operation does not require any privilege. There is a
    use-after-free bug of icsk_ulp_data of a struct inet_connection_sock. When CONFIG_TLS is enabled, user can
    install a tls context (struct tls_context) on a connected tcp socket. The context is not cleared if this
    socket is disconnected and reused as a listener. If a new socket is created from the listener, the context
    is inherited and vulnerable. The setsockopt TCP_ULP operation does not require any privilege. We recommend
    upgrading past commit 2c02d41d71f90a5168391b6a5f2954112ba2307c (CVE-2023-0461)

  - A flaw was found in the Linux Kernel. The tls_is_tx_ready() incorrectly checks for list emptiness,
    potentially accessing a type confused entry to the list_head, leaking the last byte of the confused field
    that overlaps with rec->tx_ready. (CVE-2023-1075)

  - A flaw was found in the Linux Kernel. The tun/tap sockets have their socket UID hardcoded to 0 due to a
    type confusion in their initialization function. While it will be often correct, as tuntap devices require
    CAP_NET_ADMIN, it may not always be the case, e.g., a non-root user only having that capability. This
    would make tun/tap sockets being incorrectly treated in filtering/routing decisions, possibly bypassing
    network filters. (CVE-2023-1076)

  - A flaw was found in the Linux Kernel in RDS (Reliable Datagram Sockets) protocol. The
    rds_rm_zerocopy_callback() uses list_entry() on the head of a list causing a type confusion. Local user
    can trigger this with rds_message_put(). Type confusion leads to `struct rds_msg_zcopy_info *info`
    actually points to something else that is potentially controlled by local user. It is known how to trigger
    this, which causes an out of bounds access, and a lock corruption. (CVE-2023-1078)

  - In nf_tables_updtable, if nf_tables_table_enable returns an error, nft_trans_destroy is called to free the
    transaction object. nft_trans_destroy() calls list_del(), but the transaction was never placed on a list
    -- the list head is all zeroes, this results in a NULL pointer dereference. (CVE-2023-1095)

  - Use After Free vulnerability in Linux kernel traffic control index filter (tcindex) allows Privilege
    Escalation. The imperfect hash area can be updated while packets are traversing, which will cause a use-
    after-free when 'tcf_exts_exec()' is called with the destroyed tcf_ext. A local attacker user can use this
    vulnerability to elevate its privileges to root. This issue affects Linux Kernel: from 4.14 before git
    commit ee059170b1f7e94e55fa6cadee544e176a6e59c2. (CVE-2023-1281)

  - A remote denial of service vulnerability was found in the Linux kernel's TIPC kernel module. The while
    loop in tipc_link_xmit() hits an unknown state while attempting to parse SKBs, which are not in the queue.
    Sending two small UDP packets to a system with a UDP bearer results in the CPU utilization for the system
    to instantly spike to 100%, causing a denial of service condition. (CVE-2023-1390)

  - A flaw was found in KVM. When calling the KVM_GET_DEBUGREGS ioctl, on 32-bit systems, there might be some
    uninitialized portions of the kvm_debugregs structure that could be copied to userspace, causing an
    information leak. (CVE-2023-1513)

  - A race problem was found in fs/proc/task_mmu.c in the memory management sub-component in the Linux kernel.
    This issue may allow a local attacker with user privilege to cause a denial of service. (CVE-2023-1582)

  - In the Linux kernel before 5.19, drivers/gpu/drm/arm/malidp_planes.c misinterprets the get_sg_table return
    value (expects it to be NULL in the error case, whereas it is actually an error pointer). (CVE-2023-23004)

  - The Linux kernel through 6.1.9 has a Use-After-Free in bigben_remove in drivers/hid/hid-bigbenff.c via a
    crafted USB device because the LED controllers remain registered for too long. (CVE-2023-25012)

  - hci_conn_cleanup in net/bluetooth/hci_conn.c in the Linux kernel through 6.2.9 has a use-after-free
    (observed in hci_conn_hash_flush) because of calls to hci_dev_put and hci_conn_put. There is a double free
    that may lead to privilege escalation. (CVE-2023-28464)

  - do_tls_getsockopt in net/tls/tls_main.c in the Linux kernel through 6.2.6 lacks a lock_sock call, leading
    to a race condition (with a resultant use-after-free or NULL pointer dereference). (CVE-2023-28466)

  - An issue was discovered in the Linux kernel before 5.13.3. lib/seq_buf.c has a seq_buf_putmem_hex buffer
    overflow. (CVE-2023-28772)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209778");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-April/028739.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-5753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0394");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0461");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1075");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1382");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1390");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1513");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28327");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28328");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28464");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28466");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28772");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5753");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-28772");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150200_24_148-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-default-base-5.3.18-150200.24.148.1.150200.9.71.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-default-devel-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-devel-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-macros-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-obs-build-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-preempt-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-preempt-devel-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-source-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-syms-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'reiserfs-kmp-default-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-default-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-default-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-default-base-5.3.18-150200.24.148.1.150200.9.71.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-default-base-5.3.18-150200.24.148.1.150200.9.71.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-default-devel-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-default-devel-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-devel-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-macros-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-obs-build-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-obs-build-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-preempt-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-preempt-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-preempt-devel-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-preempt-devel-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-source-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-syms-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-syms-5.3.18-150200.24.148.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'cluster-md-kmp-default-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'dlm-kmp-default-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'gfs2-kmp-default-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'ocfs2-kmp-default-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'kernel-default-livepatch-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']},
    {'reference':'kernel-default-livepatch-devel-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']},
    {'reference':'kernel-livepatch-5_3_18-150200_24_148-default-1-150200.5.3.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']},
    {'reference':'kernel-default-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'kernel-default-base-5.3.18-150200.24.148.1.150200.9.71.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'kernel-default-devel-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'kernel-obs-build-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'kernel-syms-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'reiserfs-kmp-default-5.3.18-150200.24.148.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
