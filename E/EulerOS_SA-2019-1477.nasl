#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124801);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2013-7265",
    "CVE-2013-7266",
    "CVE-2013-7267",
    "CVE-2013-7268",
    "CVE-2013-7269",
    "CVE-2013-7270",
    "CVE-2013-7271",
    "CVE-2013-7281",
    "CVE-2013-7339",
    "CVE-2013-7421",
    "CVE-2013-7446",
    "CVE-2014-0038",
    "CVE-2014-0049",
    "CVE-2014-0069",
    "CVE-2014-0077",
    "CVE-2014-0100",
    "CVE-2014-0101",
    "CVE-2014-0102",
    "CVE-2014-0131",
    "CVE-2014-0155",
    "CVE-2014-0181"
  );
  script_bugtraq_id(
    64677,
    64739,
    64741,
    64742,
    64743,
    64744,
    64746,
    64747,
    65255,
    65588,
    65909,
    65943,
    65952,
    65961,
    66101,
    66351,
    66678,
    66688,
    67034,
    72322
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1477)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - The pn_recvmsg function in net/phonet/datagram.c in the
    Linux kernel before 3.12.4 updates a certain length
    value before ensuring that an associated data structure
    has been initialized, which allows local users to
    obtain sensitive information from kernel stack memory
    via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system
    call.(CVE-2013-7265)

  - The mISDN_sock_recvmsg function in
    drivers/isdn/mISDN/socket.c in the Linux kernel before
    3.12.4 does not ensure that a certain length value is
    consistent with the size of an associated data
    structure, which allows local users to obtain sensitive
    information from kernel memory via a (1) recvfrom, (2)
    recvmmsg, or (3) recvmsg system call.(CVE-2013-7266)

  - The atalk_recvmsg function in net/appletalk/ddp.c in
    the Linux kernel before 3.12.4 updates a certain length
    value without ensuring that an associated data
    structure has been initialized, which allows local
    users to obtain sensitive information from kernel
    memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg
    system call.(CVE-2013-7267)

  - The ipx_recvmsg function in net/ipx/af_ipx.c in the
    Linux kernel before 3.12.4 updates a certain length
    value without ensuring that an associated data
    structure has been initialized, which allows local
    users to obtain sensitive information from kernel
    memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg
    system call.(CVE-2013-7268)

  - The nr_recvmsg function in net/netrom/af_netrom.c in
    the Linux kernel before 3.12.4 updates a certain length
    value without ensuring that an associated data
    structure has been initialized, which allows local
    users to obtain sensitive information from kernel
    memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg
    system call.(CVE-2013-7269)

  - The packet_recvmsg function in net/packet/af_packet.c
    in the Linux kernel before 3.12.4 updates a certain
    length value before ensuring that an associated data
    structure has been initialized, which allows local
    users to obtain sensitive information from kernel
    memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg
    system call.(CVE-2013-7270)

  - The x25_recvmsg function in net/x25/af_x25.c in the
    Linux kernel before 3.12.4 updates a certain length
    value without ensuring that an associated data
    structure has been initialized, which allows local
    users to obtain sensitive information from kernel
    memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg
    system call.(CVE-2013-7271)

  - The dgram_recvmsg function in net/ieee802154/dgram.c in
    the Linux kernel before 3.12.4 updates a certain length
    value without ensuring that an associated data
    structure has been initialized, which allows local
    users to obtain sensitive information from kernel stack
    memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg
    system call.(CVE-2013-7281)

  - A NULL pointer dereference flaw was found in the
    rds_ib_laddr_check() function in the Linux kernel's
    implementation of Reliable Datagram Sockets (RDS). A
    local, unprivileged user could use this flaw to crash
    the system.(CVE-2013-7339)

  - A flaw was found in the way the Linux kernel's Crypto
    subsystem handled automatic loading of kernel modules.
    A local user could use this flaw to load any installed
    kernel module, and thus increase the attack surface of
    the running kernel.(CVE-2013-7421)

  - A flaw was found in the Linux kernel's implementation
    of Unix sockets. A server polling for client-socket
    data could put the peer socket on a wait list the peer
    socket could then close the connection, making the
    reference on the wait list no longer valid. This could
    lead to bypassing the permissions on a Unix socket and
    packets being injected into the stream, and could also
    panic the machine (denial of service).(CVE-2013-7446)

  - The compat_sys_recvmmsg function in net/compat.c in the
    Linux kernel before 3.13.2, when CONFIG_X86_X32 is
    enabled, allows local users to gain privileges via a
    recvmmsg system call with a crafted timeout pointer
    parameter.(CVE-2014-0038)

  - Buffer overflow in the complete_emulated_mmio function
    in arch/x86/kvm/x86.c in the Linux kernel before 3.13.6
    allows guest OS users to execute arbitrary code on the
    host OS by leveraging a loop that triggers an invalid
    memory copy affecting certain cancel_work_item
    data.(CVE-2014-0049)

  - The cifs_iovec_write function in fs/cifs/file.c in the
    Linux kernel through 3.13.5 does not properly handle
    uncached write operations that copy fewer than the
    requested number of bytes, which allows local users to
    obtain sensitive information from kernel memory, cause
    a denial of service (memory corruption and system
    crash), or possibly gain privileges via a writev system
    call with a crafted pointer.(CVE-2014-0069)

  - drivers/vhost/net.c in the Linux kernel before 3.13.10,
    when mergeable buffers are disabled, does not properly
    validate packet lengths, which allows guest OS users to
    cause a denial of service (memory corruption and host
    OS crash) or possibly gain privileges on the host OS
    via crafted packets, related to the handle_rx and
    get_rx_bufs functions.(CVE-2014-0077)

  - Race condition in the inet_frag_intern function in
    net/ipv4/inet_fragment.c in the Linux kernel through
    3.13.6 allows remote attackers to cause a denial of
    service (use-after-free error) or possibly have
    unspecified other impact via a large series of
    fragmented ICMP Echo Request packets to a system with a
    heavy CPU load.(CVE-2014-0100)

  - A flaw was found in the way the Linux kernel processed
    an authenticated COOKIE_ECHO chunk during the
    initialization of an SCTP connection. A remote attacker
    could use this flaw to crash the system by initiating a
    specially crafted SCTP handshake in order to trigger a
    NULL pointer dereference on the system.(CVE-2014-0101)

  - The keyring_detect_cycle_iterator function in
    security/keys/keyring.c in the Linux kernel through
    3.13.6 does not properly determine whether keyrings are
    identical, which allows local users to cause a denial
    of service (OOPS) via crafted keyctl
    commands.(CVE-2014-0102)

  - Use-after-free vulnerability in the skb_segment
    function in net/core/skbuff.c in the Linux kernel
    through 3.13.6 allows attackers to obtain sensitive
    information from kernel memory by leveraging the
    absence of a certain orphaning
    operation.(CVE-2014-0131)

  - The ioapic_deliver function in virt/kvm/ioapic.c in the
    Linux kernel through 3.14.1 does not properly validate
    the kvm_irq_delivery_to_apic return value, which allows
    guest OS users to cause a denial of service (host OS
    crash) via a crafted entry in the redirection table of
    an I/O APIC. NOTE: the affected code was moved to the
    ioapic_service function before the vulnerability was
    announced.(CVE-2014-0155)

  - It was found that the permission checks performed by
    the Linux kernel when a netlink message was received
    were not sufficient. A local, unprivileged user could
    potentially bypass these restrictions by passing a
    netlink socket as stdout or stderr to a more privileged
    process and altering the output of this
    process.(CVE-2014-0181)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1477
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2db0b02");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0100");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel recvmmsg Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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
