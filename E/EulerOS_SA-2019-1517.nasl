#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124970);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-4312",
    "CVE-2014-2673",
    "CVE-2014-3185",
    "CVE-2014-7841",
    "CVE-2015-0568",
    "CVE-2015-2830",
    "CVE-2015-7884",
    "CVE-2015-8569",
    "CVE-2016-10741",
    "CVE-2016-4951",
    "CVE-2016-5340",
    "CVE-2016-8633",
    "CVE-2017-1000111",
    "CVE-2017-13694",
    "CVE-2017-15306",
    "CVE-2017-16535",
    "CVE-2017-5986",
    "CVE-2017-6348",
    "CVE-2017-7541",
    "CVE-2018-15471"
  );
  script_bugtraq_id(
    66477,
    69781,
    71081,
    73699
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1517)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - A memory corruption flaw was found in the way the USB
    ConnectTech WhiteHEAT serial driver processed
    completion commands sent via USB Request Blocks
    buffers. An attacker with physical access to the system
    could use this flaw to crash the system or,
    potentially, escalate their privileges on the
    system.(CVE-2014-3185i1/4%0

  - Use-after-free vulnerability in the msm_set_crop
    function in drivers/media/video/msm/msm_camera.c in the
    MSM-Camera driver for the Linux kernel 3.x, as used in
    Qualcomm Innovation Center (QuIC) Android contributions
    for MSM devices and other products, allows attackers to
    gain privileges or cause a denial of service (memory
    corruption) via an application that makes a crafted
    ioctl call.(CVE-2015-0568i1/4%0

  - The vivid_fb_ioctl function in
    drivers/media/platform/vivid/vivid-osd.c in the Linux
    kernel through 4.3.3 does not initialize a certain
    structure member, which allows local users to obtain
    sensitive information from kernel memory via a crafted
    application.(CVE-2015-7884i1/4%0

  - The usb_get_bos_descriptor function in
    drivers/usb/core/config.c in the Linux kernel can allow
    a local users to cause a denial of service
    (out-of-bounds read and system crash) or possibly have
    unspecified other impact via a crafted USB
    device.(CVE-2017-16535i1/4%0

  - The ACPI parsing functionality in the Linux kernel does
    not flush the node and node_ext caches which causes a
    kernel stack dump. This allows local users to obtain
    sensitive information from kernel memory and use this
    information to bypass the KASLR protection mechanism by
    creating and applying crafted ACPI
    table.(CVE-2017-13694i1/4%0

  - The is_ashmem_file function in
    drivers/staging/android/ashmem.c in a certain Qualcomm
    Innovation Center (QuIC) Android patch for the Linux
    kernel 3.x mishandles pointer validation within the
    KGSL Linux Graphics Module, which allows attackers to
    bypass intended access restrictions by using the
    /ashmem string as the dentry name.(CVE-2016-5340i1/4%0

  - It was found that the Linux kernel did not properly
    account file descriptors passed over the unix socket
    against the process limit. A local user could use this
    flaw to exhaust all available memory on the
    system.(CVE-2013-4312i1/4%0

  - Kernel memory corruption due to a buffer overflow was
    found in brcmf_cfg80211_mgmt_tx() function in Linux
    kernels from v3.9-rc1 to v4.13-rc1. The vulnerability
    can be triggered by sending a crafted NL80211_CMD_FRAME
    packet via netlink. This flaw is unlikely to be
    triggered remotely as certain userspace code is needed
    for this. An unprivileged local user could use this
    flaw to induce kernel memory corruption on the system,
    leading to a crash. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out,
    although it is unlikely.(CVE-2017-7541i1/4%0

  - A flaw in the netback module allowed frontends to
    control mapping of requests to request queues. An
    attacker can change this mapping by requesting invalid
    mapping requests allowing the (usually privileged)
    backend to access out-of-bounds memory access for
    reading and writing.(CVE-2018-15471i1/4%0

  - A buffer overflow vulnerability due to a lack of input
    filtering of incoming fragmented datagrams was found in
    the IP-over-1394 driver firewire-net in a fragment
    handling code in the Linux kernel. The vulnerability
    exists since firewire supported IPv4, i.e. since
    version 2.6.31 (year 2009) till version v4.9-rc4. A
    maliciously formed fragment with a respectively large
    datagram offset would cause a memcpy() past the
    datagram buffer, which would cause a system panic or
    possible arbitrary code execution.The flaw requires
    firewire-net module to be loaded and is remotely
    exploitable from connected firewire devices, but not
    over a local network.(CVE-2016-8633i1/4%0

  - It was found that the Linux kernel can hit a BUG_ON()
    statement in the __xfs_get_blocks() in the
    fs/xfs/xfs_aops.c because of a race condition between
    direct and memory-mapped I/O associated with a hole in
    a file that is handled with BUG_ON() instead of an I/O
    failure. This allows a local unprivileged attacker to
    cause a system crash and a denial of
    service.(CVE-2016-10741i1/4%0

  - A vulnerability was found in the Linux kernel. The
    pointer to the netlink socket attribute is not checked,
    which could cause a null pointer dereference when
    parsing the nested attributes in function
    tipc_nl_publ_dump(). This allows local users to cause a
    DoS.(CVE-2016-4951i1/4%0

  - It was reported that with Linux kernel, earlier than
    version v4.10-rc8, an application may trigger a BUG_ON
    in sctp_wait_for_sndbuf if the socket tx buffer is
    full, a thread is waiting on it to queue more data, and
    meanwhile another thread peels off the association
    being used by the first thread.(CVE-2017-5986i1/4%0

  - The kvm_vm_ioctl_check_extension function in
    arch/powerpc/kvm/powerpc.c in the Linux kernel before
    4.13.11 allows local users to cause a denial of service
    (NULL pointer dereference and system crash) via a
    KVM_CHECK_EXTENSION KVM_CAP_PPC_HTM ioctl call to
    /dev/kvm.(CVE-2017-15306i1/4%0

  - A flaw was found in the way the Linux kernel's 32-bit
    emulation implementation handled forking or closing of
    a task with an 'int80' entry. A local user could
    potentially use this flaw to escalate their privileges
    on the system.(CVE-2015-2830i1/4%0

  - A flaw was found in the way the Linux kernel's SCTP
    implementation validated INIT chunks when performing
    Address Configuration Change (ASCONF). A remote
    attacker could use this flaw to crash the system by
    sending a specially crafted SCTP packet to trigger a
    NULL pointer dereference on the
    system.(CVE-2014-7841i1/4%0

  - A race condition issue leading to a use-after-free flaw
    was found in the way the raw packet sockets are
    implemented in the Linux kernel networking subsystem
    handling synchronization. A local user able to open a
    raw packet socket (requires the CAP_NET_RAW capability)
    can use this issue to crash the
    system.(CVE-2017-1000111)

  - A flaw was found in the way the Linux kernel performed
    forking inside of a transaction. A local, unprivileged
    user on a PowerPC system that supports transactional
    memory could use this flaw to crash the
    system.(CVE-2014-2673i1/4%0

  - The hashbin_delete function in net/irda/irqueue.c in
    the Linux kernel improperly manages lock dropping,
    which allows local users to cause a denial of service
    (deadlock) via crafted operations on IrDA
    devices.(CVE-2017-6348i1/4%0

  - An out-of-bounds flaw was found in the kernel, where
    the length of the sockaddr parameter was not checked in
    the pptp_bind() and pptp_connect() functions. As a
    result, more kernel memory was copied out than
    required, leaking information from the kernel stack
    (including kernel addresses). A local system user could
    exploit this flaw to bypass kernel ASLR or leak other
    information.(CVE-2015-8569i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1517
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01e2415c");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7541");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
