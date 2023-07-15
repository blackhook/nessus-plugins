#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124806);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2014-0049",
    "CVE-2014-7822",
    "CVE-2014-9803",
    "CVE-2015-8374",
    "CVE-2016-2547",
    "CVE-2016-7425",
    "CVE-2016-8655",
    "CVE-2017-0523",
    "CVE-2017-5577",
    "CVE-2017-5970",
    "CVE-2017-7346",
    "CVE-2017-8797",
    "CVE-2017-8831",
    "CVE-2017-18075",
    "CVE-2017-18216",
    "CVE-2017-1000112",
    "CVE-2018-6554",
    "CVE-2018-13098",
    "CVE-2018-16862",
    "CVE-2018-20511"
  );
  script_bugtraq_id(65909, 72347);

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1482)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - An information-leak vulnerability was found in the
    kernel when it truncated a file to a smaller size which
    consisted of an inline extent that was compressed. The
    data between the new file size and the old file size
    was not discarded and the number of bytes used by the
    inode were not correctly decremented, which gave the
    wrong report for callers of the stat(2) syscall. This
    wasted metadata space and allowed for the truncated
    data to be leaked, and data corruption or loss to
    occur. A caller of the clone ioctl could exploit this
    flaw by using only standard file-system operations
    without root access to read the truncated
    data.(CVE-2015-8374i1/4%0

  - crypto/pcrypt.c in the Linux kernel, before 4.14.13,
    mishandles freeing instances, allowing a local user
    able to access the AF_ALG-based AEAD interface
    (CONFIG_CRYPTO_USER_API_AEAD) and pcrypt
    (CONFIG_CRYPTO_PCRYPT) to cause a denial of service
    (kfree of an incorrect pointer) or possibly have
    unspecified other impact by executing a crafted
    sequence of system calls. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2017-18075i1/4%0

  - An elevation of privilege vulnerability in the Qualcomm
    Wi-Fi driver could enable a local malicious application
    to execute arbitrary code within the context of the
    kernel. This issue is rated as High because it first
    requires compromising a privileged process. Product:
    Android. Versions: N/A. Android ID: A-32835279.
    References: QC-CR#1096945.(CVE-2017-0523i1/4%0

  - The saa7164_bus_get function in
    drivers/media/pci/saa7164/saa7164-bus.c in the Linux
    kernel through 4.10.14 allows local users to cause a
    denial of service (out-of-bounds array access) or
    possibly have unspecified other impact by changing a
    certain sequence-number value, aka a 'double fetch'
    vulnerability.(CVE-2017-8831i1/4%0

  - A flaw was found in the way the Linux kernel's splice()
    system call validated its parameters. On certain file
    systems, a local, unprivileged user could use this flaw
    to write past the maximum file size, and thus crash the
    system.(CVE-2014-7822i1/4%0

  - The vc4_get_bcl function in
    drivers/gpu/drm/vc4/vc4_gem.c in the VideoCore DRM
    driver in the Linux kernel before 4.9.7 does not set an
    errno value upon certain overflow detections allowing
    local users to cause a denial of service (incorrect
    pointer dereference and OOPS) via inconsistent size
    values in a VC4_SUBMIT_CL ioctl call.(CVE-2017-5577i1/4%0

  - In fs/ocfs2/cluster/nodemanager.c in the Linux kernel
    before 4.15, local users can cause a denial of service
    (NULL pointer dereference and BUG) because a required
    mutex is not used.(CVE-2017-18216i1/4%0

  - A race condition issue leading to a use-after-free flaw
    was found in the way the raw packet sockets
    implementation in the Linux kernel networking subsystem
    handled synchronization while creating the TPACKET_V3
    ring buffer. A local user able to open a raw packet
    socket (requires the CAP_NET_RAW capability) could use
    this flaw to elevate their privileges on the
    system.(CVE-2016-8655i1/4%0

  - An exploitable memory corruption flaw was found in the
    Linux kernel. The append path can be erroneously
    switched from UFO to non-UFO in ip_ufo_append_data()
    when building an UFO packet with MSG_MORE option. If
    unprivileged user namespaces are available, this flaw
    can be exploited to gain root
    privileges.(CVE-2017-1000112i1/4%0

  - A security flaw was found in the Linux kernel in a way
    that the cleancache subsystem clears an inode after the
    final file truncation (removal). The new file created
    with the same inode may contain leftover pages from
    cleancache and the old file data instead of the new
    one.(CVE-2018-16862i1/4%0

  - arch/arm64/ include /asm/pgtable.h in the Linux kernel
    before 3.15-rc5-next-20140519, as used in Android
    before 2016-07-05 on Nexus 5X and 6P devices,
    mishandles execute-only pages, which allows attackers
    to gain privileges via a crafted application, aka
    Android internal bug 28557020.(CVE-2014-9803i1/4%0

  - A heap-buffer overflow vulnerability was found in the
    arcmsr_iop_message_xfer() function in
    'drivers/scsi/arcmsr/arcmsr_hba.c' file in the Linux
    kernel through 4.8.2. The function does not restrict a
    certain length field, which allows local users to gain
    privileges or cause a denial of service via an
    ARCMSR_MESSAGE_WRITE_WQBUFFER control code. This can
    potentially cause kernel heap corruption and arbitrary
    kernel code execution.(CVE-2016-7425i1/4%0

  - An issue was discovered in the Linux kernel before
    4.18.11. The ipddp_ioctl function in
    drivers/net/appletalk/ipddp.c allows local users to
    obtain sensitive kernel address information by
    leveraging CAP_NET_ADMIN to read the ipddp_route dev
    and next fields via an SIOCFINDIPDDPRT ioctl
    call.(CVE-2018-20511i1/4%0

  - A memory leak in the irda_bind function in
    net/irda/af_irda.c in the Linux kernel, through 4.16,
    allows local users to cause a denial of service due to
    a memory consumption by repeatedly binding an AF_IRDA
    socket.(CVE-2018-6554i1/4%0

  - sound/core/timer.c in the Linux kernel before 4.4.1
    employs a locking approach that does not consider slave
    timer instances, which allows local users to cause a
    denial of service (race condition, use-after-free, and
    system crash) via a crafted ioctl
    call.(CVE-2016-2547i1/4%0

  - Buffer overflow in the complete_emulated_mmio function
    in arch/x86/kvm/x86.c in the Linux kernel before 3.13.6
    allows guest OS users to execute arbitrary code on the
    host OS by leveraging a loop that triggers an invalid
    memory copy affecting certain cancel_work_item
    data.(CVE-2014-0049i1/4%0

  - An issue was discovered in the F2FS filesystem code in
    the Linux kernel in fs/f2fs/inode.c. A denial of
    service due to a slab out-of-bounds read can occur for
    a crafted f2fs filesystem image in which FI_EXTRA_ATTR
    is set in an inode.(CVE-2018-13098i1/4%0

  - A vulnerability was found in the Linux kernel where
    having malicious IP options present would cause the
    ipv4_pktinfo_prepare() function to drop/free the dst.
    This could result in a system crash or possible
    privilege escalation.(CVE-2017-5970i1/4%0

  - In the Linux kernel's vmw_gb_surface_define_ioctl()
    function, in 'drivers/gpu/drm/vmwgfx/vmwgfx_surface.c'
    file, a 'req-i1/4zmip_levels' is a user-controlled value
    which is later used as a loop count limit. This allows
    local unprivileged user to cause a denial of service by
    a kernel lockup via a crafted ioctl call for a
    '/dev/dri/renderD*' device.(CVE-2017-7346i1/4%0

  - It was found that the NFSv4 server in the Linux kernel
    did not properly validate layout type when processing
    NFSv4 pNFS LAYOUTGET and GETDEVICEINFO operands. A
    remote attacker could use this flaw to soft-lockup the
    system and thus cause denial of
    service.(CVE-2017-8797i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1482
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3610568");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9803");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-18075");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
