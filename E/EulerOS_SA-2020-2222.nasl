#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(141697);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2015-4036",
    "CVE-2016-1583",
    "CVE-2017-13168",
    "CVE-2017-13693",
    "CVE-2017-13694",
    "CVE-2017-13695",
    "CVE-2017-14340",
    "CVE-2018-10323",
    "CVE-2018-10876",
    "CVE-2018-10877",
    "CVE-2018-1093",
    "CVE-2018-5995",
    "CVE-2018-6554",
    "CVE-2018-7492",
    "CVE-2018-7995",
    "CVE-2018-9422",
    "CVE-2019-18808",
    "CVE-2019-20096",
    "CVE-2019-20812"
  );
  script_bugtraq_id(
    74664
  );

  script_name(english:"EulerOS Virtualization 3.0.2.2 : kernel (EulerOS-SA-2020-2222)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - Array index error in the tcm_vhost_make_tpg function in
    drivers/vhost/scsi.c in the Linux kernel before 4.0
    might allow guest OS users to cause a denial of service
    (memory corruption) or possibly have unspecified other
    impact via a crafted VHOST_SCSI_SET_ENDPOINT ioctl
    call. NOTE: the affected function was renamed to
    vhost_scsi_make_tpg before the vulnerability was
    announced.(CVE-2015-4036)

  - The ecryptfs_privileged_open function in
    fs/ecryptfs/kthread.c in the Linux kernel before 4.6.3
    allows local users to gain privileges or cause a denial
    of service (stack memory consumption) via vectors
    involving crafted mmap calls for /proc pathnames,
    leading to recursive pagefault handling.(CVE-2016-1583)

  - It was found that SCSI driver in the Linux kernel can
    improperly access userspace memory outside the provided
    buffer. A local privileged attacker could potentially
    use this flaw to expose information from the kernel
    memory.(CVE-2017-13168)

  - The acpi_ds_create_operands() function in
    drivers/acpi/acpica/dsutils.c in the Linux kernel
    through 4.12.9 does not flush the operand cache and
    causes a kernel stack dump, which allows local users to
    obtain sensitive information from kernel memory and
    bypass the KASLR protection mechanism (in the kernel
    through 4.9) via a crafted ACPI table.(CVE-2017-13693)

  - The acpi_ps_complete_final_op() function in
    drivers/acpi/acpica/psobject.c in the Linux kernel
    through 4.12.9 does not flush the node and node_ext
    caches and causes a kernel stack dump, which allows
    local users to obtain sensitive information from kernel
    memory and bypass the KASLR protection mechanism (in
    the kernel through 4.9) via a crafted ACPI
    table.(CVE-2017-13694)

  - The acpi_ns_evaluate() function in
    drivers/acpi/acpica/nseval.c in the Linux kernel
    through 4.12.9 does not flush the operand cache and
    causes a kernel stack dump, which allows local users to
    obtain sensitive information from kernel memory and
    bypass the KASLR protection mechanism (in the kernel
    through 4.9) via a crafted ACPI table.(CVE-2017-13695)

  - The XFS_IS_REALTIME_INODE macro in fs/xfs/xfs_linux.h
    in the Linux kernel before 4.13.2 does not verify that
    a filesystem has a realtime device, which allows local
    users to cause a denial of service (NULL pointer
    dereference and OOPS) via vectors related to setting an
    RHINHERIT flag on a directory.(CVE-2017-14340)

  - The xfs_bmap_extents_to_btree function in
    fs/xfs/libxfs/xfs_bmap.c in the Linux kernel through
    4.16.3 allows local users to cause a denial of service
    (xfs_bmapi_write NULL pointer dereference) via a
    crafted xfs image.(CVE-2018-10323)

  - A flaw was found in Linux kernel in the ext4 filesystem
    code. A use-after-free is possible in
    ext4_ext_remove_space() function when mounting and
    operating a crafted ext4 image.(CVE-2018-10876)

  - A flaw was found in the Linux kernel ext4 filesystem.
    An out-of-bound access is possible in the
    ext4_ext_drop_refs() function when operating on a
    crafted ext4 filesystem image.(CVE-2018-10877)

  - The pcpu_embed_first_chunk function in mm/percpu.c in
    the Linux kernel through 4.14.14 allows local users to
    obtain sensitive address information by reading dmesg
    data from a(CVE-2018-5995)

  - Memory leak in the irda_bind function in
    net/irda/af_irda.c and later in
    drivers/staging/irda/net/af_irda.c in the Linux kernel
    before 4.17 allows local users to cause a denial of
    service (memory consumption) by repeatedly binding an
    AF_IRDA socket.(CVE-2018-6554)

  - A NULL pointer dereference was found in the
    net/rds/rdma.c __rds_rdma_map() function in the Linux
    kernel before 4.14.7 allowing local attackers to cause
    a system panic and a denial-of-service, related to
    RDS_GET_MR and RDS_GET_MR_FOR_DEST.(CVE-2018-7492)

  - ** DISPUTED ** Race condition in the
    store_int_with_restart() function in
    arch/x86/kernel/cpu/mcheck/mce.c in the Linux kernel
    through 4.15.7 allows local users to cause a denial of
    service (panic) by leveraging root access to write to
    the check_interval file in a
    /sys/devices/system/machinecheck/machinecheck<cpu
    number> directory. NOTE: a third party has indicated
    that this report is not security
    relevant.(CVE-2018-7995)

  - Non-optimized code for key handling of shared futexes
    was found in the Linux kernel in the form of unbounded
    contention time due to the page lock for real-time
    users. Before the fix, the page lock was an
    unnecessarily heavy lock for the futex path that
    protected too much. After the fix, the page lock is
    only required in a specific corner case.(CVE-2018-9422)

  - A memory leak in the ccp_run_sha_cmd() function in
    drivers/crypto/ccp/ccp-ops.c in the Linux kernel
    through 5.3.9 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-128c66429247.(CVE-2019-18808)

  - In the Linux kernel before 5.1, there is a memory leak
    in __feat_register_sp() in net/dccp/feat.c, which may
    cause denial of service, aka
    CID-1d3ff0950e2b.(CVE-2019-20096)

  - An issue was discovered in the Linux kernel before
    5.4.7. The prb_calc_retire_blk_tmo() function in
    net/packet/af_packet.c can result in a denial of
    service (CPU consumption and soft lockup) in a certain
    failure case involving TPACKET_V3, aka
    CID-b43d1f9f7067.(CVE-2019-20812)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2222
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a073a88");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9422");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["kernel-3.10.0-862.14.1.6_74",
        "kernel-devel-3.10.0-862.14.1.6_74",
        "kernel-headers-3.10.0-862.14.1.6_74",
        "kernel-tools-3.10.0-862.14.1.6_74",
        "kernel-tools-libs-3.10.0-862.14.1.6_74"];

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
