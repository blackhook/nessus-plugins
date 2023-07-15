#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135614);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2014-3180",
    "CVE-2017-18549",
    "CVE-2017-18550",
    "CVE-2017-18551",
    "CVE-2017-18595",
    "CVE-2018-5803",
    "CVE-2018-1000026",
    "CVE-2019-3874",
    "CVE-2019-10220",
    "CVE-2019-11833",
    "CVE-2019-12382",
    "CVE-2019-12456",
    "CVE-2019-12819",
    "CVE-2019-15090",
    "CVE-2019-15212",
    "CVE-2019-15216",
    "CVE-2019-15916",
    "CVE-2019-15924",
    "CVE-2019-16233",
    "CVE-2019-18806",
    "CVE-2019-19447",
    "CVE-2019-19537",
    "CVE-2019-19965",
    "CVE-2019-20054"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.2 : kernel (EulerOS-SA-2020-1452)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc.Security Fix(es):In the Linux kernel
    5.0.21, mounting a crafted ext4 filesystem image,
    performing some operations, and unmounting can lead to
    a use-after-free in ext4_put_super in fs/ext4/super.c,
    related to dump_orphan_list in
    fs/ext4/super.c.(CVE-2019-19447)Linux kernel CIFS
    implementation, version 4.9.0 is vulnerable to a
    relative paths injection in directory entry
    lists.(CVE-2019-10220)** DISPUTED ** In kernel/compat.c
    in the Linux kernel before 3.17, as used in Google
    Chrome OS and other products, there is a possible
    out-of-bounds read. restart_syscall uses uninitialized
    data when restarting compat_sys_nanosleep. NOTE: this
    is disputed because the code path is
    unreachable.(CVE-2014-3180)In the Linux kernel before
    5.0.6, there is a NULL pointer dereference in
    drop_sysctl_table() in fs/proc/proc_sysctl.c, related
    to put_links, aka
    CID-23da9588037e(CVE-2019-20054)pointer dereference in
    drivers/scsi/libsas/sas_discover.c because of
    mishandling of port disconnection during discovery,
    related to a PHY down race condition, aka
    CID-f70267f379b5.(CVE-2019-19965)'In the Linux kernel
    before 5.2.10, there is a race condition bug that can
    be caused by a malicious USB device in the USB
    character device driver layer, aka CID-303911cfc5b9.
    This affects
    drivers/usb/core/file.c.(CVE-2019-19537)Linux Linux
    kernel version at least v4.8 onwards, probably well
    before contains a Insufficient input validation
    vulnerability in bnx2x network card driver that can
    result in DoS: Network card firmware assertion takes
    card off-line. This attack appear to be exploitable via
    An attacker on a must pass a very large, specially
    crafted packet to the bnx2x card. This can be done from
    an untrusted guest
    VM..(CVE-2018-1000026)drivers/scsi/qla2xxx/qla_os.c in
    the Linux kernel 5.2.14 does not check the
    alloc_workqueue return value, leading to a NULL pointer
    dereference.(CVE-2019-16233)The SCTP socket buffer used
    by a userspace application is not accounted by the
    cgroups subsystem. An attacker can use this flaw to
    cause a denial of service attack. Kernel 3.10.x and
    4.18.x branches are believed to be
    vulnerable.(CVE-2019-3874)fs/ext4/extents.c in the
    Linux kernel through 5.1.2 does not zero out the unused
    memory region in the extent tree block, which might
    allow local users to obtain sensitive information by
    reading uninitialized data in the
    filesystem.(CVE-2019-11833)A memory leak in the
    ql_alloc_large_buffers() function in
    driverset/ethernet/qlogic/qla3xxx.c in the Linux kernel
    before 5.3.5 allows local users to cause a denial of
    service (memory consumption) by triggering
    pci_dma_mapping_error() failures, aka
    CID-1acb8f2a7a9f.(CVE-2019-18806)An issue was
    discovered in the Linux kernel before 5.0.11.
    fm10k_init_module in
    driverset/ethernet/intel/fm10k/fm10k_main.c has a NULL
    pointer dereference because there is no -ENOMEM upon an
    alloc_workqueue failure.(CVE-2019-15924)An issue was
    discovered in the Linux kernel before 5.0.1. There is a
    memory leak in register_queue_kobjects() in
    net/coreet-sysfs.c, which will cause denial of
    service.(CVE-2019-15916)An issue was discovered in the
    Linux kernel before 5.0.14. There is a NULL pointer
    dereference caused by a malicious USB device in the
    drivers/usb/misc/yurex.c driver.(CVE-2019-15216)An
    issue was discovered in the Linux kernel before 5.1.8.
    There is a double-free caused by a malicious USB device
    in the drivers/usb/misc/rio500.c
    driver.(CVE-2019-15212)An issue was discovered in
    drivers/scsi/qedi/qedi_dbg.c in the Linux kernel before
    5.1.12. In the qedi_dbg_* family of functions, there is
    an out-of-bounds read.(CVE-2019-15090)An issue was
    discovered in the Linux kernel before 5.0. The function
    __mdiobus_register() in driverset/phy/mdio_bus.c calls
    put_device(), which will trigger a fixed_mdio_bus_init
    use-after-free. This will cause a denial of
    service.(CVE-2019-12819)** DISPUTED ** An issue was
    discovered in the MPT3COMMAND case in _ctl_ioctl_main
    in drivers/scsi/mpt3sas/mpt3sas_ctl.c in the Linux
    kernel through 5.1.5. It allows local users to cause a
    denial of service or possibly have unspecified other
    impact by changing the value of ioc_number between two
    kernel reads of that value, aka a 'double fetch'
    vulnerability. NOTE: a third party reports that this is
    unexploitable because the doubly fetched value is not
    used.(CVE-2019-12456)An issue was discovered in
    drm_load_edid_firmware in
    drivers/gpu/drm/drm_edid_load.c in the Linux kernel
    through 5.1.5. There is an unchecked kstrdup of fwstr,
    which might allow an attacker to cause a denial of
    service (NULL pointer dereference and system crash).
    NOTE: The vendor disputes this issues as not being a
    vulnerability because kstrdup() returning NULL is
    handled sufficiently and there is no chance for a NULL
    pointer dereference.(CVE-2019-12382)In the Linux Kernel
    before version 4.15.8, 4.14.25, 4.9.87, 4.4.121,
    4.1.51, and 3.2.102, an error in the
    '_sctp_make_chunk()' function
    (net/sctp/sm_make_chunk.c) when handling SCTP packets
    length can be exploited to cause a kernel
    crash.(CVE-2018-5803)An issue was discovered in the
    Linux kernel before 4.14.11. A double free may be
    caused by the function allocate_trace_buffer in the
    file kernel/trace/trace.c.(CVE-2017-18595)An issue was
    discovered in drivers/i2c/i2c-core-smbus.c in the Linux
    kernel before 4.14.15. There is an out of bounds write
    in the function
    i2c_smbus_xfer_emulated.(CVE-2017-18551)An issue was
    discovered in drivers/scsi/aacraid/commctrl.c in the
    Linux kernel before 4.13. There is potential exposure
    of kernel stack memory because aac_get_hba_info does
    not initialize the hbainfo structure.(CVE-2017-18550)An
    issue was discovered in drivers/scsi/aacraid/commctrl.c
    in the Linux kernel before 4.13. There is potential
    exposure of kernel stack memory because
    aac_send_raw_srb does not initialize the reply
    structure.(CVE-2017-18549)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1452
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f070bac5");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10220");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-3180");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_72",
        "kernel-devel-3.10.0-862.14.1.6_72",
        "kernel-headers-3.10.0-862.14.1.6_72",
        "kernel-tools-3.10.0-862.14.1.6_72",
        "kernel-tools-libs-3.10.0-862.14.1.6_72",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_72",
        "perf-3.10.0-862.14.1.6_72",
        "python-perf-3.10.0-862.14.1.6_72"];

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
