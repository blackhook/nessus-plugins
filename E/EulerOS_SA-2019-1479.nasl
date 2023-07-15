#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124803);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2014-0196",
    "CVE-2014-0206",
    "CVE-2014-1444",
    "CVE-2014-1445",
    "CVE-2014-1446",
    "CVE-2014-1690",
    "CVE-2014-1737",
    "CVE-2014-1738",
    "CVE-2014-1739",
    "CVE-2014-1874",
    "CVE-2014-2038",
    "CVE-2014-2309",
    "CVE-2014-2523",
    "CVE-2014-2568",
    "CVE-2014-2672",
    "CVE-2014-2673",
    "CVE-2014-2706",
    "CVE-2014-2851",
    "CVE-2014-3122",
    "CVE-2014-3144",
    "CVE-2014-3145"
  );
  script_bugtraq_id(
    64952,
    64953,
    64954,
    65180,
    65459,
    65688,
    66095,
    66279,
    66348,
    66477,
    66492,
    66591,
    66779,
    67162,
    67199,
    67282,
    67300,
    67302,
    67309,
    67321,
    68048,
    68176
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1479)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - The n_tty_write function in drivers/tty/n_tty.c in the
    Linux kernel through 3.14.3 does not properly manage
    tty driver access in the 'LECHO i1/4+ !OPOST' case, which
    allows local users to cause a denial of service (memory
    corruption and system crash) or gain privileges by
    triggering a race condition involving read and write
    operations with long strings.(CVE-2014-0196)

  - Array index error in the aio_read_events_ring function
    in fs/aio.c in the Linux kernel through 3.15.1 allows
    local users to obtain sensitive information from kernel
    memory via a large head value.(CVE-2014-0206)

  - The fst_get_iface function in drivers/net/wan/farsync.c
    in the Linux kernel before 3.11.7 does not properly
    initialize a certain data structure, which allows local
    users to obtain sensitive information from kernel
    memory by leveraging the CAP_NET_ADMIN capability for
    an SIOCWANDEV ioctl call.(CVE-2014-1444)

  - The wanxl_ioctl function in drivers/net/wan/wanxl.c in
    the Linux kernel before 3.11.7 does not properly
    initialize a certain data structure, which allows local
    users to obtain sensitive information from kernel
    memory via an ioctl call.(CVE-2014-1445)

  - The yam_ioctl function in drivers/net/hamradio/yam.c in
    the Linux kernel before 3.12.8 does not initialize a
    certain structure member, which allows local users to
    obtain sensitive information from kernel memory by
    leveraging the CAP_NET_ADMIN capability for an
    SIOCYAMGCFG ioctl call.(CVE-2014-1446)

  - The help function in net/netfilter/nf_nat_irc.c in the
    Linux kernel before 3.12.8 allows remote attackers to
    obtain sensitive information from kernel memory by
    establishing an IRC DCC session in which incorrect
    packet data is transmitted during use of the NAT mangle
    feature.(CVE-2014-1690)

  - A flaw was found in the way the Linux kernel's floppy
    driver handled user space provided data in certain
    error code paths while processing FDRAWCMD IOCTL
    commands. A local user with write access to /dev/fdX
    could use this flaw to free (using the kfree()
    function) arbitrary kernel memory. (CVE-2014-1737,
    Important)

  - It was found that the Linux kernel's floppy driver
    leaked internal kernel memory addresses to user space
    during the processing of the FDRAWCMD IOCTL command. A
    local user with write access to /dev/fdX could use this
    flaw to obtain information about the kernel heap
    arrangement. (CVE-2014-1738, Low)

  - Note: A local user with write access to /dev/fdX could
    use these two flaws (CVE-2014-1737 in combination with
    CVE-2014-1738) to escalate their privileges on the
    system.(CVE-2014-1737)

  - A flaw was found in the way the Linux kernel's floppy
    driver handled user space provided data in certain
    error code paths while processing FDRAWCMD IOCTL
    commands. A local user with write access to /dev/fdX
    could use this flaw to free (using the kfree()
    function) arbitrary kernel memory. (CVE-2014-1737,
    Important)

  - It was found that the Linux kernel's floppy driver
    leaked internal kernel memory addresses to user space
    during the processing of the FDRAWCMD IOCTL command. A
    local user with write access to /dev/fdX could use this
    flaw to obtain information about the kernel heap
    arrangement. (CVE-2014-1738, Low)

  - Note: A local user with write access to /dev/fdX could
    use these two flaws (CVE-2014-1737 in combination with
    CVE-2014-1738) to escalate their privileges on the
    system.(CVE-2014-1738)

  - An information leak flaw was found in the way the Linux
    kernel handled media device enumerate entities IOCTL
    requests. A local user able to access the /dev/media0
    device file could use this flaw to leak kernel memory
    bytes.(CVE-2014-1739)

  - The security_context_to_sid_core function in
    security/selinux/ss/services.c in the Linux kernel
    before 3.13.4 allows local users to cause a denial of
    service (system crash) by leveraging the CAP_MAC_ADMIN
    capability to set a zero-length security
    context.(CVE-2014-1874)

  - The nfs_can_extend_write function in fs/nfs/write.c in
    the Linux kernel before 3.13.3 relies on a write
    delegation to extend a write operation without a
    certain up-to-date verification, which allows local
    users to obtain sensitive information from kernel
    memory in opportunistic circumstances by writing to a
    file in an NFS filesystem and then reading the same
    file.(CVE-2014-2038)

  - The ip6_route_add function in net/ipv6/route.c in the
    Linux kernel through 3.13.6 does not properly count the
    addition of routes, which allows remote attackers to
    cause a denial of service (memory consumption) via a
    flood of ICMPv6 Router Advertisement
    packets.(CVE-2014-2309)

  - net/netfilter/nf_conntrack_proto_dccp.c in the Linux
    kernel through 3.13.6 uses a DCCP header pointer
    incorrectly, which allows remote attackers to cause a
    denial of service (system crash) or possibly execute
    arbitrary code via a DCCP packet that triggers a call
    to the (1) dccp_new, (2) dccp_packet, or (3) dccp_error
    function.(CVE-2014-2523)

  - Use-after-free vulnerability in the nfqnl_zcopy
    function in net/netfilter/nfnetlink_queue_core.c in the
    Linux kernel through 3.13.6 allows attackers to obtain
    sensitive information from kernel memory by leveraging
    the absence of a certain orphaning operation. NOTE: the
    affected code was moved to the skb_zerocopy function in
    net/core/skbuff.c before the vulnerability was
    announced.(CVE-2014-2568)

  - It was found that a remote attacker could use a race
    condition flaw in the ath_tx_aggr_sleep() function to
    crash the system by creating large network traffic on
    the system's Atheros 9k wireless network
    adapter.(CVE-2014-2672)

  - A flaw was found in the way the Linux kernel performed
    forking inside of a transaction. A local, unprivileged
    user on a PowerPC system that supports transactional
    memory could use this flaw to crash the
    system.(CVE-2014-2673)

  - A race condition flaw was found in the way the Linux
    kernel's mac80211 subsystem implementation handled
    synchronization between TX and STA wake-up code paths.
    A remote attacker could use this flaw to crash the
    system.(CVE-2014-2706)

  - A use-after-free flaw was found in the way the
    ping_init_sock() function of the Linux kernel handled
    the group_info reference counter. A local, unprivileged
    user could use this flaw to crash the system or,
    potentially, escalate their privileges on the
    system.(CVE-2014-2851)

  - It was found that the try_to_unmap_cluster() function
    in the Linux kernel's Memory Managment subsystem did
    not properly handle page locking in certain cases,
    which could potentially trigger the BUG_ON() macro in
    the mlock_vma_page() function. A local, unprivileged
    user could use this flaw to crash the
    system.(CVE-2014-3122)

  - The (1) BPF_S_ANC_NLATTR and (2) BPF_S_ANC_NLATTR_NEST
    extension implementations in the sk_run_filter function
    in net/core/filter.c in the Linux kernel through 3.14.3
    do not check whether a certain length value is
    sufficiently large, which allows local users to cause a
    denial of service (integer underflow and system crash)
    via crafted BPF instructions. NOTE: the affected code
    was moved to the __skb_get_nlattr and
    __skb_get_nlattr_nest functions before the
    vulnerability was announced.(CVE-2014-3144)

  - The BPF_S_ANC_NLATTR_NEST extension implementation in
    the sk_run_filter function in net/core/filter.c in the
    Linux kernel through 3.14.3 uses the reverse order in a
    certain subtraction, which allows local users to cause
    a denial of service (over-read and system crash) via
    crafted BPF instructions. NOTE: the affected code was
    moved to the __skb_get_nlattr_nest function before the
    vulnerability was announced.(CVE-2014-3145)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1479
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d6a0a29");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-1874");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

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

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_42",
        "kernel-devel-3.10.0-862.14.1.6_42",
        "kernel-headers-3.10.0-862.14.1.6_42",
        "kernel-tools-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_42",
        "perf-3.10.0-862.14.1.6_42",
        "python-perf-3.10.0-862.14.1.6_42"];

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
