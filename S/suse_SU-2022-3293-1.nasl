#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3293-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(165230);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2016-3695",
    "CVE-2020-36516",
    "CVE-2021-4037",
    "CVE-2021-33135",
    "CVE-2022-2588",
    "CVE-2022-2639",
    "CVE-2022-2663",
    "CVE-2022-2873",
    "CVE-2022-2905",
    "CVE-2022-2938",
    "CVE-2022-2959",
    "CVE-2022-2977",
    "CVE-2022-3028",
    "CVE-2022-3078",
    "CVE-2022-20368",
    "CVE-2022-20369",
    "CVE-2022-28356",
    "CVE-2022-28693",
    "CVE-2022-32250",
    "CVE-2022-36879",
    "CVE-2022-36946",
    "CVE-2022-39188",
    "CVE-2022-39190"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3293-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2022:3293-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:3293-1 advisory.

  - The einj_error_inject function in drivers/acpi/apei/einj.c in the Linux kernel allows local users to
    simulate hardware errors and consequently cause a denial of service by leveraging failure to disable APEI
    error injection through EINJ when securelevel is set. (CVE-2016-3695)

  - An issue was discovered in the Linux kernel through 5.16.11. The mixed IPID assignment method with the
    hash-based IPID assignment policy allows an off-path attacker to inject data into a victim's TCP session
    or terminate that session. (CVE-2020-36516)

  - Uncontrolled resource consumption in the Linux kernel drivers for Intel(R) SGX may allow an authenticated
    user to potentially enable denial of service via local access. (CVE-2021-33135)

  - A vulnerability was found in the fs/inode.c:inode_init_owner() function logic of the LInux kernel that
    allows local users to create files for the XFS file-system with an unintended group ownership and with
    group execution and SGID permission bits set, in a scenario where a directory is SGID and belongs to a
    certain group and is writable by a user who is not a member of this group. This can lead to excessive
    permissions granted in case when they should not. This vulnerability is similar to the previous
    CVE-2018-13405 and adds the missed fix for the XFS. (CVE-2021-4037)

  - Product: AndroidVersions: Android kernelAndroid ID: A-224546354References: Upstream kernel
    (CVE-2022-20368)

  - In v4l2_m2m_querybuf of v4l2-mem2mem.c, there is a possible out of bounds write due to improper input
    validation. This could lead to local escalation of privilege with System execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-223375145References: Upstream kernel (CVE-2022-20369)

  - kernel: a use-after-free in cls_route filter implementation may lead to privilege escalation
    (CVE-2022-2588)

  - An integer coercion error was found in the openvswitch kernel module. Given a sufficiently large number of
    actions, while copying and reserving memory for a new action of a new flow, the reserve_sfa_size()
    function does not return -EMSGSIZE as expected, potentially leading to an out-of-bounds write access. This
    flaw allows a local user to crash or potentially escalate their privileges on the system. (CVE-2022-2639)

  - An issue was found in the Linux kernel in nf_conntrack_irc where the message handling can be confused and
    incorrectly matches the message. A firewall may be able to be bypassed when users are using unencrypted
    IRC with nf_conntrack_irc configured. (CVE-2022-2663)

  - In the Linux kernel before 5.17.1, a refcount leak bug was found in net/llc/af_llc.c. (CVE-2022-28356)

  - A flaw was found in hw. Mis-trained branch predictions for return instructions may allow arbitrary
    speculative code execution under certain microarchitecture-dependent conditions. (CVE-2022-23816)
    (CVE-2022-28693)

  - An out-of-bounds memory access flaw was found in the Linux kernel Intel's iSMT SMBus host controller
    driver in the way a user triggers the I2C_SMBUS_BLOCK_DATA (with the ioctl I2C_SMBUS) with malicious input
    data. This flaw allows a local user to crash the system. (CVE-2022-2873)

  - An out-of-bounds memory read flaw was found in the Linux kernel's BPF subsystem in how a user calls the
    bpf_tail_call function with a key larger than the max_entries of the map. This flaw allows a local user to
    gain unauthorized access to data. (CVE-2022-2905)

  - A flaw was found in the Linux kernel's implementation of Pressure Stall Information. While the feature is
    disabled by default, it could allow an attacker to crash the system or have other memory-corruption side
    effects. (CVE-2022-2938)

  - A race condition was found in the Linux kernel's watch queue due to a missing lock in pipe_resize_ring().
    The specific flaw exists within the handling of pipe buffers. The issue results from the lack of proper
    locking when performing operations on an object. This flaw allows a local user to crash the system or
    escalate their privileges on the system. (CVE-2022-2959)

  - A flaw was found in the Linux kernel implementation of proxied virtualized TPM devices. On a system where
    virtualized TPM devices are configured (this is not the default) a local attacker can create a use-after-
    free and create a situation where it may be possible to escalate privileges on the system. (CVE-2022-2977)

  - A race condition was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem)
    when multiple calls to xfrm_probe_algs occurred simultaneously. This flaw could allow a local attacker to
    potentially trigger an out-of-bounds write or leak kernel heap memory by performing an out-of-bounds read
    and copying it into a socket. (CVE-2022-3028)

  - An issue was discovered in the Linux kernel through 5.16-rc6. There is a lack of check after calling
    vzalloc() and lack of free after allocation in drivers/media/test-drivers/vidtv/vidtv_s302m.c.
    (CVE-2022-3078)

  - net/netfilter/nf_tables_api.c in the Linux kernel through 5.18.1 allows a local user (able to create
    user/net namespaces) to escalate privileges to root because an incorrect NFT_STATEFUL_EXPR check leads to
    a use-after-free. (CVE-2022-32250)

  - An issue was discovered in the Linux kernel through 5.18.14. xfrm_expand_policies in
    net/xfrm/xfrm_policy.c can cause a refcount to be dropped twice. (CVE-2022-36879)

  - nfqnl_mangle in net/netfilter/nfnetlink_queue.c in the Linux kernel through 5.18.14 allows remote
    attackers to cause a denial of service (panic) because, in the case of an nf_queue verdict with a one-byte
    nfta_payload attribute, an skb_pull can encounter a negative skb->len. (CVE-2022-36946)

  - An issue was discovered in include/asm-generic/tlb.h in the Linux kernel before 5.19. Because of a race
    condition (unmap_mapping_range versus munmap), a device driver can free a page while it still has stale
    TLB entries. This only occurs in situations with VM_PFNMAP VMAs. (CVE-2022-39188)

  - An issue was discovered in net/netfilter/nf_tables_api.c in the Linux kernel before 5.19.6. A denial of
    service can occur upon binding to an already bound chain. (CVE-2022-39190)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1023051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1032323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202265");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203159");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-September/012273.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c794ce97");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-3695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36516");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33135");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4037");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20368");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20369");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28356");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2873");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32250");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39188");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39190");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32250");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150400_24_21-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-64kb-5.14.21-150400.24.21.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-64kb-5.14.21-150400.24.21.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-64kb-devel-5.14.21-150400.24.21.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-64kb-devel-5.14.21-150400.24.21.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.21.2.150400.24.7.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.21.2.150400.24.7.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-default-extra-5.14.21-150400.24.21.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'sle-we-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-default-extra-5.14.21-150400.24.21.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'sle-we-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-devel-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-devel-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-macros-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-macros-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-source-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-source-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.21.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.21.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-zfcpdump-5.14.21-150400.24.21.2', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-zfcpdump-5.14.21-150400.24.21.2', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-legacy-release-15.4', 'sles-release-15.4']},
    {'reference':'cluster-md-kmp-64kb-5.14.21-150400.24.21.2', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'cluster-md-kmp-default-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dlm-kmp-64kb-5.14.21-150400.24.21.2', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dlm-kmp-default-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-allwinner-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-altera-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-amazon-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-amd-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-amlogic-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-apm-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-apple-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-arm-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-broadcom-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-cavium-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-exynos-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-freescale-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-hisilicon-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-lg-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-marvell-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-mediatek-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-nvidia-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-qcom-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-renesas-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-rockchip-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-socionext-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-sprd-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dtb-xilinx-5.14.21-150400.24.21.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gfs2-kmp-64kb-5.14.21-150400.24.21.2', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gfs2-kmp-default-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-64kb-5.14.21-150400.24.21.2', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-64kb-devel-5.14.21-150400.24.21.2', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-64kb-extra-5.14.21-150400.24.21.2', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-64kb-livepatch-devel-5.14.21-150400.24.21.2', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-64kb-optional-5.14.21-150400.24.21.2', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-debug-5.14.21-150400.24.21.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-debug-devel-5.14.21-150400.24.21.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-debug-livepatch-devel-5.14.21-150400.24.21.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.21.2.150400.24.7.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-default-base-rebuild-5.14.21-150400.24.21.2.150400.24.7.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-default-extra-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-default-livepatch-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-default-livepatch-devel-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-default-optional-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-devel-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-kvmsmall-5.14.21-150400.24.21.2', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-kvmsmall-5.14.21-150400.24.21.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-kvmsmall-devel-5.14.21-150400.24.21.2', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-kvmsmall-devel-5.14.21-150400.24.21.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-kvmsmall-livepatch-devel-5.14.21-150400.24.21.2', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-kvmsmall-livepatch-devel-5.14.21-150400.24.21.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-macros-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-obs-qa-5.14.21-150400.24.21.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-source-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-source-vanilla-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.21.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-zfcpdump-5.14.21-150400.24.21.2', 'cpu':'s390x', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kselftests-kmp-64kb-5.14.21-150400.24.21.2', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kselftests-kmp-default-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ocfs2-kmp-64kb-5.14.21-150400.24.21.2', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ocfs2-kmp-default-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'reiserfs-kmp-64kb-5.14.21-150400.24.21.2', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.21.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'cluster-md-kmp-default-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'dlm-kmp-default-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'gfs2-kmp-default-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'ocfs2-kmp-default-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'kernel-default-livepatch-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-default-livepatch-devel-5.14.21-150400.24.21.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-livepatch-5_14_21-150400_24_21-default-1-150400.9.3.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']}
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
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-64kb / cluster-md-kmp-default / dlm-kmp-64kb / etc');
}
