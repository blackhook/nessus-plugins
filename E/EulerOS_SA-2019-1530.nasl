#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124983);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-6380",
    "CVE-2014-4157",
    "CVE-2014-4654",
    "CVE-2014-9585",
    "CVE-2015-2041",
    "CVE-2015-7566",
    "CVE-2015-8956",
    "CVE-2016-5696",
    "CVE-2016-9588",
    "CVE-2017-14051",
    "CVE-2017-14106",
    "CVE-2017-15299",
    "CVE-2017-15868",
    "CVE-2017-16533",
    "CVE-2017-7616",
    "CVE-2017-9984",
    "CVE-2018-10880",
    "CVE-2018-13053",
    "CVE-2018-14611",
    "CVE-2018-5750"
  );
  script_bugtraq_id(
    63887,
    68083,
    68162,
    71990,
    72729
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1530)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The acpi_smbus_hc_add function in drivers/acpi/sbshc.c
    in the Linux kernel through 4.14.15 allows local users
    to obtain sensitive address information by reading
    dmesg data from an SBS HC printk call.(CVE-2018-5750i1/4%0

  - An issue was discovered in the btrfs filesystem code in
    the Linux kernel. A use-after-free is possible in
    try_merge_free_space() when mounting a crafted btrfs
    image due to a lack of chunk type flag checks in
    btrfs_check_chunk_valid() in the fs/btrfs/volumes.c
    function. This could lead to a denial of service or
    other unspecified impact.(CVE-2018-14611i1/4%0

  - A flaw was found in the way the Linux kernel visor
    driver handles certain invalid USB device descriptors.
    The driver assumes that the device always has at least
    one bulk OUT endpoint. By using a specially crafted USB
    device (without a bulk OUT endpoint), an unprivileged
    user with physical access could trigger a kernel
    NULL-pointer dereference and cause a system panic
    (denial of service).(CVE-2015-7566i1/4%0

  - It was found that the RFC 5961 challenge ACK rate
    limiting as implemented in the Linux kernel's
    networking subsystem allowed an off-path attacker to
    leak certain information about a given connection by
    creating congestion on the global challenge ACK rate
    limit counter and then measuring the changes by probing
    packets. An off-path attacker could use this flaw to
    either terminate TCP connection and/or inject payload
    into non-secured TCP connection between two endpoints
    on the network.(CVE-2016-5696i1/4%0

  - It was found that the Bluebooth Network Encapsulation
    Protocol (BNEP) implementation did not validate the
    type of second socket passed to the BNEPCONNADD
    ioctl(), which could lead to memory corruption. A local
    user with the CAP_NET_ADMIN capability can use this for
    denial of service (crash or data corruption) or
    possibly for privilege escalation. Due to the nature of
    the flaw, privilege escalation cannot be fully ruled
    out, although we feel it is unlikely.(CVE-2017-15868i1/4%0

  - A vulnerability was found in the key management
    subsystem of the Linux kernel. An update on an
    uninstantiated key could cause a kernel panic, leading
    to denial of service (DoS).(CVE-2017-15299i1/4%0

  - The rfcomm_sock_bind function in
    net/bluetooth/rfcomm/sock.c in the Linux kernel before
    4.2 allows local users to obtain sensitive information
    or cause a denial of service (NULL pointer dereference)
    via vectors involving a bind system call on a Bluetooth
    RFCOMM socket.(CVE-2015-8956i1/4%0

  - arch/mips/include/asm/thread_info.h in the Linux kernel
    before 3.14.8 on the MIPS platform does not configure
    _TIF_SECCOMP checks on the fast system-call path, which
    allows local users to bypass intended PR_SET_SECCOMP
    restrictions by executing a crafted application without
    invoking a trace or audit subsystem.(CVE-2014-4157i1/4%0

  - A flaw was found in the Linux kernel's ext4 filesystem
    code. A stack-out-of-bounds write in
    ext4_update_inline_data() is possible when mounting and
    writing to a crafted ext4 image. An attacker could use
    this to cause a system crash and a denial of
    service.(CVE-2018-10880i1/4%0

  - The aac_send_raw_srb function in
    drivers/scsi/aacraid/commctrl.c in the Linux kernel
    through 3.12.1 does not properly validate a certain
    size value, which allows local users to cause a denial
    of service (invalid pointer dereference) or possibly
    have unspecified other impact via an
    FSACTL_SEND_RAW_SRB ioctl call that triggers a crafted
    SRB command.(CVE-2013-6380i1/4%0

  - Linux kernel built with the KVM visualization support
    (CONFIG_KVM), with nested visualization(nVMX) feature
    enabled(nested=1), is vulnerable to an uncaught
    exception issue. It could occur if an L2 guest was to
    throw an exception which is not handled by an L1
    guest.(CVE-2016-9588i1/4%0

  - A flaw was found in the alarm_timer_nsleep() function
    in kernel/time/alarmtimer.c in the Linux kernel. The
    ktime_add_safe() function is not used and an integer
    overflow can happen causing an alarm not to fire if
    using a large relative timeout.(CVE-2018-13053i1/4%0

  - net/llc/sysctl_net_llc.c in the Linux kernel before
    3.19 uses an incorrect data type in a sysctl table,
    which allows local users to obtain potentially
    sensitive information from kernel memory or possibly
    have unspecified other impact by accessing a sysctl
    entry.(CVE-2015-2041i1/4%0

  - Incorrect error handling in the set_mempolicy() and
    mbind() compat syscalls in 'mm/mempolicy.c' in the
    Linux kernel allows local users to obtain sensitive
    information from uninitialized stack data by triggering
    failure of a certain bitmap operation.(CVE-2017-7616i1/4%0

  - The snd_msnd_interrupt function in
    sound/isa/msnd/msnd_pinnacle.c in the Linux kernel
    through 4.11.7 allows local users to cause a denial of
    service (over-boundary access) or possibly have
    unspecified other impact by changing the value of a
    message queue head pointer between two kernel reads of
    that value, aka a 'double fetch'
    vulnerability.(CVE-2017-9984i1/4%0

  - An integer overflow was discovered in the
    qla2x00_sysfs_write_optrom_ctl function in
    drivers/scsi/qla2xxx/qla_attr.c in the Linux kernel
    through 4.12.10. This flaw allows local users to cause
    a denial of service (memory corruption and system
    crash) by leveraging root access.(CVE-2017-14051i1/4%0

  - A use-after-free flaw was found in the way the Linux
    kernel's Advanced Linux Sound Architecture (ALSA)
    implementation handled user controls. A local,
    privileged user could use this flaw to crash the
    system.(CVE-2014-4654i1/4%0

  - An information leak flaw was found in the way the Linux
    kernel's Virtual Dynamic Shared Object (vDSO)
    implementation performed address randomization. A
    local, unprivileged user could use this flaw to leak
    kernel memory addresses to user-space.(CVE-2014-9585i1/4%0

  - The usbhid_parse function in
    drivers/hid/usbhid/hid-core.c in the Linux kernel,
    before 4.13.8, allows local users to cause a denial of
    service (out-of-bounds read and system crash) or
    possibly have unspecified other impact via a crafted
    USB device.(CVE-2017-16533i1/4%0

  - A divide-by-zero vulnerability was found in the
    __tcp_select_window function in the Linux kernel. This
    can result in a kernel panic causing a local denial of
    service.(CVE-2017-14106i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1530
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b19f2a9");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9984");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
