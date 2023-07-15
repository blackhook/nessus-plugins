#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124992);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2015-8830",
    "CVE-2016-8399",
    "CVE-2017-0861",
    "CVE-2017-13166",
    "CVE-2017-13215",
    "CVE-2017-18017",
    "CVE-2017-5753",
    "CVE-2017-5754",
    "CVE-2017-7184",
    "CVE-2017-7558",
    "CVE-2017-9725",
    "CVE-2018-1000026",
    "CVE-2018-10902",
    "CVE-2018-14646",
    "CVE-2018-3693",
    "CVE-2018-5390",
    "CVE-2018-5803"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1539)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of instructions past bounds check. The flaw
    relies on the presence of a precisely-defined
    instruction sequence in the privileged code and the
    fact that memory writes occur to an address which
    depends on the untrusted value. Such writes cause an
    update into the microprocessor's data cache even for
    speculatively executed instructions that never actually
    commit (retire). As a result, an unprivileged attacker
    could use this flaw to influence speculative execution
    and/or read privileged memory by conducting targeted
    cache side-channel attacks.(CVE-2018-3693)

  - A flaw named SegmentSmack was found in the way the
    Linux kernel handled specially crafted TCP packets. A
    remote attacker could use this flaw to trigger time and
    calculation expensive calls to tcp_collapse_ofo_queue()
    and tcp_prune_ofo_queue() functions by sending
    specially modified packets within ongoing TCP sessions
    which could lead to a CPU saturation and hence a denial
    of service on the system. Maintaining the denial of
    service condition requires continuous two-way TCP
    sessions to a reachable open port, thus the attacks
    cannot be performed using spoofed IP
    addresses.(CVE-2018-5390)

  - It was found that the raw midi kernel driver does not
    protect against concurrent access which leads to a
    double realloc (double free) in
    snd_rawmidi_input_params() and
    snd_rawmidi_output_status() which are part of
    snd_rawmidi_ioctl() handler in rawmidi.c file. A
    malicious local attacker could possibly use this for
    privilege escalation.(CVE-2018-10902)

  - Integer overflow in the aio_setup_single_vector
    function in fs/aio.c in the Linux kernel 4.0 allows
    local users to cause a denial of service or possibly
    have unspecified other impact via a large AIO iovec.
    NOTE: this vulnerability exists because of a
    CVE-2012-6701 regression.(CVE-2015-8830)

  - A flaw was found in the Linux networking subsystem
    where a local attacker with CAP_NET_ADMIN capabilities
    could cause an out-of-bounds memory access by creating
    a smaller-than-expected ICMP header and sending to its
    destination via sendto().(CVE-2016-8399)

  - Out-of-bounds kernel heap access vulnerability was
    found in xfrm, kernel's IP framework for transforming
    packets. An error dealing with netlink messages from an
    unprivileged user leads to arbitrary read/write and
    privilege escalation.(CVE-2017-7184)

  - The Linux kernel was found to be vulnerable to a NULL
    pointer dereference bug in the __netlink_ns_capable()
    function in the net/netlink/af_netlink.c file. A local
    attacker could exploit this when a net namespace with a
    netnsid is assigned to cause a kernel panic and a
    denial of service.i1/4^CVE-2018-14646i1/4%0

  - A flaw was found where the kernel truncated the value
    used to indicate the size of a buffer which it would
    later become zero using an untruncated value. This can
    corrupt memory outside of the original
    allocation.(CVE-2017-9725)

  - A bug in the 32-bit compatibility layer of the ioctl
    handling code of the v4l2 video driver in the Linux
    kernel has been found. A memory protection mechanism
    ensuring that user-provided buffers always point to a
    userspace memory were disabled, allowing destination
    address to be in a kernel space. This flaw could be
    exploited by an attacker to overwrite a kernel memory
    from an unprivileged userspace process, leading to
    privilege escalation.(CVE-2017-13166)

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of instructions (a commonly used performance
    optimization). There are three primary variants of the
    issue which differ in the way the speculative execution
    can be exploited. Variant CVE-2017-5754 relies on the
    fact that, on impacted microprocessors, during
    speculative execution of instruction permission faults,
    exception generation triggered by a faulting access is
    suppressed until the retirement of the whole
    instruction block. In a combination with the fact that
    memory accesses may populate the cache even when the
    block is being dropped and never committed (executed),
    an unprivileged local attacker could use this flaw to
    read privileged (kernel space) memory by conducting
    targeted cache side-channel attacks. Note:
    CVE-2017-5754 affects Intel x86-64 microprocessors. AMD
    x86-64 microprocessors are not affected by this
    issue.(CVE-2017-5754)

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of instructions (a commonly used performance
    optimization). There are three primary variants of the
    issue which differ in the way the speculative execution
    can be exploited. Variant CVE-2017-5753 triggers the
    speculative execution by performing a bounds-check
    bypass. It relies on the presence of a
    precisely-defined instruction sequence in the
    privileged code as well as the fact that memory
    accesses may cause allocation into the microprocessor's
    data cache even for speculatively executed instructions
    that never actually commit (retire). As a result, an
    unprivileged attacker could use this flaw to cross the
    syscall boundary and read privileged memory by
    conducting targeted cache side-channel
    attacks.(CVE-2017-5753)

  - A flaw was found in the Linux kernel's skcipher
    component, which affects the skcipher_recvmsg function.
    Attackers using a specific input can lead to a
    privilege escalation.i1/4^CVE-2017-13215i1/4%0

  - The tcpmss_mangle_packet function in
    net/netfilter/xt_TCPMSS.c in the Linux kernel before
    4.11, and 4.9.x before 4.9.36, allows remote attackers
    to cause a denial of service (use-after-free and memory
    corruption) or possibly have unspecified other impact
    by leveraging the presence of xt_TCPMSS in an iptables
    action. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is unlikely.i1/4^CVE-2017-18017i1/4%0

  - A kernel data leak due to an out-of-bound read was
    found in the Linux kernel in
    inet_diag_msg_sctp{,l}addr_fill() and
    sctp_get_sctp_info() functions present since version
    4.7-rc1 through version 4.13. A data leak happens when
    these functions fill in sockaddr data structures used
    to export socket's diagnostic information. As a result,
    up to 100 bytes of the slab data could be leaked to a
    userspace.i1/4^CVE-2017-7558i1/4%0

  - Use-after-free vulnerability in the snd_pcm_info()
    function in the ALSA subsystem in the Linux kernel
    allows attackers to induce a kernel memory corruption
    and possibly crash or lock up a system. Due to the
    nature of the flaw, a privilege escalation cannot be
    fully ruled out, although we believe it is
    unlikely.i1/4^CVE-2017-0861i1/4%0

  - Improper validation in the bnx2x network card driver of
    the Linux kernel version 4.15 can allow for denial of
    service (DoS) attacks via a packet with a gso_size
    larger than ~9700 bytes. Untrusted guest VMs can
    exploit this vulnerability in the host machine, causing
    a crash in the network card.i1/4^CVE-2018-1000026i1/4%0

  - An error in the '_sctp_make_chunk()' function
    (net/sctp/sm_make_chunk.c) when handling SCTP, packet
    length can be exploited by a malicious local user to
    cause a kernel crash and a DoS.i1/4^CVE-2018-5803i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1539
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53efaef9");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
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
