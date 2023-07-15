#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124980);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id(
    "CVE-2013-4470",
    "CVE-2014-0131",
    "CVE-2014-1874",
    "CVE-2014-3181",
    "CVE-2014-8134",
    "CVE-2014-9410",
    "CVE-2014-9428",
    "CVE-2014-9940",
    "CVE-2015-5327",
    "CVE-2015-5364",
    "CVE-2015-8787",
    "CVE-2015-8812",
    "CVE-2016-0728",
    "CVE-2016-10318",
    "CVE-2016-2069",
    "CVE-2016-4794",
    "CVE-2017-12192",
    "CVE-2017-18203",
    "CVE-2017-18344",
    "CVE-2017-6074"
  );
  script_bugtraq_id(
    63359,
    65459,
    66101,
    69779,
    71650,
    71847,
    75510
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1527)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The Linux kernel, before version 4.14.3, is vulnerable
    to a denial of service in
    drivers/md/dm.c:dm_get_from_kobject() which can be
    caused by local users leveraging a race condition with
    __dm_destroy() during creation and removal of DM
    devices. Only privileged local users (with
    CAP_SYS_ADMIN capability) can directly perform the
    ioctl operations for dm device creation and removal and
    this would typically be outside the direct control of
    the unprivileged attacker.(CVE-2017-18203i1/4%0

  - The batadv_frag_merge_packets function in
    net/batman-adv/fragmentation.c in the B.A.T.M.A.N.
    implementation in the Linux kernel through 3.18.1 uses
    an incorrect length field during a calculation of an
    amount of memory, which allows remote attackers to
    cause a denial of service (mesh-node system crash) via
    fragmented packets.(CVE-2014-9428i1/4%0

  - The regulator_ena_gpio_free function in
    drivers/regulator/core.c in the Linux kernel allows
    local users to gain privileges or cause a denial of
    service (use-after-free) via a crafted
    application.(CVE-2014-9940i1/4%0

  - The Linux kernel before 3.12, when UDP Fragmentation
    Offload (UFO) is enabled, does not properly initialize
    certain data structures, which allows local users to
    cause a denial of service (memory corruption and system
    crash) or possibly gain privileges via a crafted
    application that uses the UDP_CORK option in a
    setsockopt system call and sends both short and long
    packets, related to the ip_ufo_append_data function in
    net/ipv4/ip_output.c and the ip6_ufo_append_data
    function in net/ipv6/ip6_output.c.(CVE-2013-4470i1/4%0

  - A use-after-free flaw was found in the way the Linux
    kernel's Datagram Congestion Control Protocol (DCCP)
    implementation freed SKB (socket buffer) resources for
    a DCCP_PKT_REQUEST packet when the IPV6_RECVPKTINFO
    option is set on the socket. A local, unprivileged user
    could use this flaw to alter the kernel memory,
    allowing them to escalate their privileges on the
    system.(CVE-2017-6074i1/4%0

  - A NULL-pointer dereference vulnerability was found in
    the Linux kernel's TCP stack, in
    net/netfilter/nf_nat_redirect.c in the
    nf_nat_redirect_ipv4() function. A remote,
    unauthenticated user could exploit this flaw to create
    a system crash (denial of service).(CVE-2015-8787i1/4%0

  - A use-after-free flaw was found in the CXGB3 kernel
    driver when the network was considered to be congested.
    The kernel incorrectly misinterpreted the congestion as
    an error condition and incorrectly freed or cleaned up
    the socket buffer (skb). When the device then sent the
    skb's queued data, these structures were referenced. A
    local attacker could use this flaw to panic the system
    (denial of service) or, with a local account, escalate
    their privileges.(CVE-2015-8812i1/4%0

  - A flaw was found in the way the Linux kernel's
    networking implementation handled UDP packets with
    incorrect checksum values. A remote attacker could
    potentially use this flaw to trigger an infinite loop
    in the kernel, resulting in a denial of service on the
    system, or cause a denial of service in applications
    using the edge triggered epoll
    functionality.(CVE-2015-5364i1/4%0

  - The timer_create syscall implementation in
    kernel/time/posix-timers.c in the Linux kernel doesn't
    properly validate the sigevent-i1/4zsigev_notify field,
    which leads to out-of-bounds access in the show_timer
    function.(CVE-2017-18344i1/4%0

  - A flaw was discovered in the way the Linux kernel dealt
    with paging structures. When the kernel invalidated a
    paging structure that was not in use locally, it could,
    in principle, race against another CPU that is
    switching to a process that uses the paging structure
    in question. A local user could use a thread running
    with a stale cached virtual-i1/4zphysical translation to
    potentially escalate their privileges if the
    translation in question were writable and the physical
    page got reused for something critical (for example, a
    page table).(CVE-2016-2069i1/4%0

  - Use after free vulnerability was found in percpu using
    previously allocated memory in bpf. First
    __alloc_percpu_gfp() is called, then the memory is
    freed with free_percpu() which triggers async
    pcpu_balance_work and then pcpu_extend_area_map could
    use a chunk after it has been freed.(CVE-2016-4794i1/4%0

  - A missing authorization check in the
    fscrypt_process_policy function in fs/crypto/policy.c
    in the ext4 and f2fs filesystem encryption support in
    the Linux kernel allows a user to assign an encryption
    policy to a directory owned by a different user,
    potentially creating a denial of
    service.(CVE-2016-10318i1/4%0

  - The security_context_to_sid_core function in
    security/selinux/ss/services.c in the Linux kernel
    before 3.13.4 allows local users to cause a denial of
    service (system crash) by leveraging the CAP_MAC_ADMIN
    capability to set a zero-length security
    context.(CVE-2014-1874i1/4%0

  - The vfe31_proc_general function in
    drivers/media/video/msm/vfe/msm_vfe31.c in the
    MSM-VFE31 driver for the Linux kernel 3.x, as used in
    Qualcomm Innovation Center (QuIC) Android contributions
    for MSM devices and other products, does not validate a
    certain id value, which allows attackers to gain
    privileges or cause a denial of service (memory
    corruption) via an application that makes a crafted
    ioctl call.(CVE-2014-9410i1/4%0

  - A vulnerability was found in the Key Management sub
    component of the Linux kernel, where when trying to
    issue a KEYTCL_READ on a negative key would lead to a
    NULL pointer dereference. A local attacker could use
    this flaw to crash the kernel.(CVE-2017-12192i1/4%0

  - Out-of-bounds memory read in the x509_decode_time
    function in x509_cert_parser.c in Linux kernels 4.3-rc1
    and after.(CVE-2015-5327i1/4%0

  - It was found that the espfix functionality does not
    work for 32-bit KVM paravirtualized guests. A local,
    unprivileged guest user could potentially use this flaw
    to leak kernel stack addresses.(CVE-2014-8134i1/4%0

  - An out-of-bounds write flaw was found in the way the
    Apple Magic Mouse/Trackpad multi-touch driver handled
    Human Interface Device (HID) reports with an invalid
    size. An attacker with physical access to the system
    could use this flaw to crash the system or,
    potentially, escalate their privileges on the
    system.(CVE-2014-3181i1/4%0

  - A use-after-free flaw was found in the way the Linux
    kernel's key management subsystem handled keyring
    object reference counting in certain error path of the
    join_session_keyring() function. A local, unprivileged
    user could use this flaw to escalate their privileges
    on the system.(CVE-2016-0728i1/4%0

  - Use-after-free vulnerability in the skb_segment
    function in net/core/skbuff.c in the Linux kernel
    through 3.13.6 allows attackers to obtain sensitive
    information from kernel memory by leveraging the
    absence of a certain orphaning
    operation.(CVE-2014-0131i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1527
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfd6ac3d");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

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

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
