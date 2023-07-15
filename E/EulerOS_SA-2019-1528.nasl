#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124981);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2014-2038",
    "CVE-2014-3917",
    "CVE-2014-4508",
    "CVE-2014-8480",
    "CVE-2015-3339",
    "CVE-2015-4001",
    "CVE-2015-4002",
    "CVE-2015-8962",
    "CVE-2016-1576",
    "CVE-2016-2085",
    "CVE-2016-4997",
    "CVE-2016-7913",
    "CVE-2016-7916",
    "CVE-2016-9777",
    "CVE-2017-7482",
    "CVE-2017-15115",
    "CVE-2017-15265",
    "CVE-2017-16526",
    "CVE-2017-17448",
    "CVE-2018-8043"
  );
  script_bugtraq_id(
    65688,
    67699,
    68126,
    70710,
    74243,
    74668,
    74672
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1528)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - An out-of-bounds memory access flaw was found in the
    Linux kernel's system call auditing implementation. On
    a system with existing audit rules defined, a local,
    unprivileged user could use this flaw to leak kernel
    memory to user space or, potentially, crash the
    system.(CVE-2014-3917i1/4%0

  - The net/netfilter/nfnetlink_cthelper.c function in the
    Linux kernel through 4.14.4 does not require the
    CAP_NET_ADMIN capability for new, get, and del
    operations. This allows local users to bypass intended
    access restrictions because the nfnl_cthelper_list data
    structure is shared across all net
    namespaces.(CVE-2017-17448i1/4%0

  - A race condition flaw was found between the chown and
    execve system calls. When changing the owner of a
    setuid user binary to root, the race condition could
    momentarily make the binary setuid root. A local,
    unprivileged user could potentially use this flaw to
    escalate their privileges on the
    system.(CVE-2015-3339i1/4%0

  - Keberos 5 tickets being decoded when using the RXRPC
    keys incorrectly assumes the size of a field. This
    could lead to the size-remaining variable wrapping and
    the data pointer going over the end of the buffer. This
    could possibly lead to memory corruption and possible
    privilege escalation.(CVE-2017-7482i1/4%0

  - The nfs_can_extend_write function in fs/nfs/write.c in
    the Linux kernel before 3.13.3 relies on a write
    delegation to extend a write operation without a
    certain up-to-date verification, which allows local
    users to obtain sensitive information from kernel
    memory in opportunistic circumstances by writing to a
    file in an NFS filesystem and then reading the same
    file.(CVE-2014-2038i1/4%0

  - KVM in the Linux kernel before 4.8.12, when I/O APIC is
    enabled, does not properly restrict the VCPU index,
    which allows guest OS users to gain host OS privileges
    or cause a denial of service (out-of-bounds array
    access and host OS crash) via a crafted interrupt
    request, related to arch/x86/kvm/ioapic.c and
    arch/x86/kvm/ioapic.h.(CVE-2016-9777i1/4%0

  - The instruction decoder in arch/x86/kvm/emulate.c in
    the KVM subsystem in the Linux kernel before 3.18-rc2
    lacks intended decoder-table flags for certain
    RIP-relative instructions, which allows guest OS users
    to cause a denial of service (NULL pointer dereference
    and host OS crash) via a crafted
    application.(CVE-2014-8480i1/4%0

  - arch/x86/kernel/entry_32.S in the Linux kernel through
    3.15.1 on 32-bit x86 platforms, when syscall auditing
    is enabled and the sep CPU feature flag is set, allows
    local users to cause a denial of service (OOPS and
    system crash) via an invalid syscall number, as
    demonstrated by number 1000.(CVE-2014-4508i1/4%0

  - The overlayfs implementation in the Linux kernel
    through 4.5.2 does not properly restrict the mount
    namespace, which allows local users to gain privileges
    by mounting an overlayfs filesystem on top of a FUSE
    filesystem, and then executing a crafted setuid
    program.(CVE-2016-1576i1/4%0

  - A use-after-free vulnerability was found when issuing
    an ioctl to a sound device. This could allow a user to
    exploit a race condition and create memory corruption
    or possibly privilege escalation.(CVE-2017-15265i1/4%0

  - The drivers/uwb/uwbd.c in the Linux kernel, before
    4.13.6, allows local users to cause a denial of service
    (general protection fault and system crash) or possibly
    have unspecified other impact via a crafted USB
    device.(CVE-2017-16526i1/4%0

  - The Linux kernel was found vulnerable to a NULL pointer
    dereference in the
    drivers/net/phy/mdio-bcm-unimac.c:unimac_mdio_probe()
    function caused by an unchecked return value from the
    platform_get_resource() function. A successful flaw
    exploitation can cause a system panic and a denial of
    service. This flaw is believed not to be an attacker
    triggerable as bad return value can be caused by
    hardware misconfiguration.(CVE-2018-8043i1/4%0

  - A flaw was found in the Linux kernel SCSI subsystem,
    which allowed a local user to gain privileges or cause
    a denial of service (memory corruption and system
    crash) by issuing an SG_IO ioctl call while a device
    was being detached.(CVE-2015-8962i1/4%0

  - The xc2028_set_config function in
    drivers/media/tuners/tuner-xc2028.c in the Linux kernel
    before 4.6 allows local users to gain privileges or
    cause a denial of service (use-after-free) via vectors
    involving omission of the firmware name from a certain
    data structure. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2016-7913i1/4%0

  - drivers/staging/ozwpan/ozusbsvc1.c in the OZWPAN driver
    in the Linux kernel through 4.0.5 does not ensure that
    certain length values are sufficiently large, which
    allows remote attackers to cause a denial of service
    (system crash or large loop) or possibly execute
    arbitrary code via a crafted packet, related to the (1)
    oz_usb_rx and (2) oz_usb_handle_ep_data
    functions.(CVE-2015-4002i1/4%0

  - Race condition in the environ_read() function in
    'fs/proc/base.c' in the Linux kernel before 4.5.4
    allows local users to obtain sensitive information from
    kernel memory by reading a '/proc/*/environ' file
    during a process-setup time interval in which
    environment-variable copying is
    incomplete.(CVE-2016-7916i1/4%0

  - Integer signedness error in the oz_hcd_get_desc_cnf
    function in drivers/staging/ozwpan/ozhcd.c in the
    OZWPAN driver in the Linux kernel through 4.0.5 allows
    remote attackers to cause a denial of service (system
    crash) or possibly execute arbitrary code via a crafted
    packet.(CVE-2015-4001i1/4%0

  - A vulnerability was found in the Linux kernel when
    peeling off an association to the socket in another
    network namespace. All transports in this association
    are not to be rehashed and keep using the old key in
    hashtable, thus removing transports from hashtable when
    closing the socket, all transports are being freed.
    Later on a use-after-free issue could be caused when
    looking up an association and dereferencing the
    transports.(CVE-2017-15115i1/4%0

  - The evm_verify_hmac function in
    security/integrity/evm/evm_main.c in the Linux kernel
    before 4.5 does not properly copy data, which makes it
    easier for local users to forge MAC values via a timing
    side-channel attack.(CVE-2016-2085i1/4%0

  - A flaw was discovered in processing setsockopt for 32
    bit processes on 64 bit systems. This flaw will allow
    attackers to alter arbitrary kernel memory when
    unloading a kernel module. This action is usually
    restricted to root-privileged users but can also be
    leveraged if the kernel is compiled with CONFIG_USER_NS
    and CONFIG_NET_NS and the user is granted elevated
    privileges.(CVE-2016-4997i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1528
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eafe631f");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7913");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-7482");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
