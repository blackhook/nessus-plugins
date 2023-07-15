#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104578);
  script_version("3.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-1000251",
    "CVE-2017-1000370",
    "CVE-2017-10661",
    "CVE-2017-12154",
    "CVE-2017-13693",
    "CVE-2017-13694",
    "CVE-2017-13695",
    "CVE-2017-14106",
    "CVE-2017-14140",
    "CVE-2017-14489"
  );

  script_name(english:"EulerOS 2.0 SP1 : kernel (EulerOS-SA-2017-1245)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The iscsi_if_rx function in
    drivers/scsi/scsi_transport_iscsi.c in the Linux kernel
    through 4.13.2 allows local users to cause a denial of
    service (panic) by leveraging incorrect length
    validation.(CVE-2017-14489)

  - The move_pages system call in mm/migrate.c in the Linux
    kernel before 4.12.9 doesn't check the effective uid of
    the target process, enabling a local attacker to learn
    the memory layout of a setuid executable despite
    ASLR.(CVE-2017-14140)

  - The offset2lib patch as used in the Linux Kernel
    contains a vulnerability that allows a PIE binary to be
    execve()'ed with 1GB of arguments or environmental
    strings then the stack occupies the address 0x80000000
    and the PIE binary is mapped above 0x40000000
    nullifying the protection of the offset2lib patch. This
    affects Linux Kernel version 4.11.5 and earlier. This
    is a different issue than CVE-2017-1000371. This issue
    appears to be limited to i386 based
    systems.(CVE-2017-1000370)

  - Race condition in fs/timerfd.c in the Linux kernel
    before 4.10.15 allows local users to gain privileges or
    cause a denial of service (list corruption or
    use-after-free) via simultaneous file-descriptor
    operations that leverage improper might_cancel
    queueing.(CVE-2017-10661)

  - The acpi_ns_evaluate() function in
    drivers/acpi/acpica/nseval.c in the Linux kernel
    through 4.12.9 does not flush the operand cache and
    causes a kernel stack dump, which allows local users to
    obtain sensitive information from kernel memory and
    bypass the KASLR protection mechanism (in the kernel
    through 4.9) via a crafted ACPI table.(CVE-2017-13695)

  - The acpi_ps_complete_final_op() function in
    drivers/acpi/acpica/psobject.c in the Linux kernel
    through 4.12.9 does not flush the node and node_ext
    caches and causes a kernel stack dump, which allows
    local users to obtain sensitive information from kernel
    memory and bypass the KASLR protection mechanism (in
    the kernel through 4.9) via a crafted ACPI
    table.(CVE-2017-13694)

  - The acpi_ds_create_operands() function in
    drivers/acpi/acpica/dsutils.c in the Linux kernel
    through 4.12.9 does not flush the operand cache and
    causes a kernel stack dump, which allows local users to
    obtain sensitive information from kernel memory and
    bypass the KASLR protection mechanism (in the kernel
    through 4.9) via a crafted ACPI table.(CVE-2017-13693)

  - The tcp_disconnect function in net/ipv4/tcp.c in the
    Linux kernel before 4.12 allows local users to cause a
    denial of service (__tcp_select_window divide-by-zero
    error and system crash) by triggering a disconnect
    within a certain tcp_recvmsg code path.(CVE-2017-14106)

  - The native Bluetooth stack in the Linux Kernel (BlueZ),
    starting at the Linux kernel version 3.3-rc1 and up to
    and including 4.13.1, are vulnerable to a stack
    overflow vulnerability in the processing of L2CAP
    configuration responses resulting in Remote code
    execution in kernel space.(CVE-2017-1000251

  - )

  - The prepare_vmcs02 function in arch/x86/kvm/vmx.c in
    the Linux kernel through 4.13.3 does not ensure that
    the 'CR8-load exiting' and 'CR8-store exiting' L0
    vmcs02 controls exist in cases where L1 omits the 'use
    TPR shadow' vmcs12 control, which allows KVM L2 guest
    OS users to obtain read and write access to the
    hardware CR8 register.(CVE-2017-12154)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1245
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22a18c1d");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-ori");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-229.49.1.149",
        "kernel-debug-3.10.0-229.49.1.149",
        "kernel-debuginfo-3.10.0-229.49.1.149",
        "kernel-debuginfo-common-x86_64-3.10.0-229.49.1.149",
        "kernel-devel-3.10.0-229.49.1.149",
        "kernel-headers-3.10.0-229.49.1.149",
        "kernel-ori-3.10.0-229",
        "kernel-tools-3.10.0-229.49.1.149",
        "kernel-tools-libs-3.10.0-229.49.1.149",
        "perf-3.10.0-229.49.1.149",
        "python-perf-3.10.0-229.49.1.149"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

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
