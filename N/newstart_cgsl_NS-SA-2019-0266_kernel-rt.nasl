#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0266. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132499);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2011-1079",
    "CVE-2016-10905",
    "CVE-2017-18550",
    "CVE-2017-18595",
    "CVE-2018-7191",
    "CVE-2018-12207",
    "CVE-2018-20836",
    "CVE-2018-20855",
    "CVE-2018-20976",
    "CVE-2019-0154",
    "CVE-2019-0155",
    "CVE-2019-3874",
    "CVE-2019-11135",
    "CVE-2019-11487",
    "CVE-2019-11884",
    "CVE-2019-12382",
    "CVE-2019-15213",
    "CVE-2019-15538",
    "CVE-2019-15807",
    "CVE-2019-15916",
    "CVE-2019-16413",
    "CVE-2019-17075"
  );
  script_bugtraq_id(
    46616,
    107488,
    108054,
    108196,
    108299,
    108380,
    108474
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel-rt Multiple Vulnerabilities (NS-SA-2019-0266)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel-rt packages installed that are affected
by multiple vulnerabilities:

  - The bnep_sock_ioctl function in
    net/bluetooth/bnep/sock.c in the Linux kernel before
    2.6.39 does not ensure that a certain device field ends
    with a '\0' character, which allows local users to
    obtain potentially sensitive information from kernel
    stack memory, or cause a denial of service (BUG and
    system crash), via a BNEPCONNADD command.
    (CVE-2011-1079)

  - An issue was discovered in fs/gfs2/rgrp.c in the Linux
    kernel before 4.8. A use-after-free is caused by the
    functions gfs2_clear_rgrpd and read_rindex_entry.
    (CVE-2016-10905)

  - An issue was discovered in
    drivers/scsi/aacraid/commctrl.c in the Linux kernel
    before 4.13. There is potential exposure of kernel stack
    memory because aac_get_hba_info does not initialize the
    hbainfo structure. (CVE-2017-18550)

  - An issue was discovered in the Linux kernel before
    4.14.11. A double free may be caused by the function
    allocate_trace_buffer in the file kernel/trace/trace.c.
    (CVE-2017-18595)

  - Improper invalidation for page table updates by a
    virtual guest operating system for multiple Intel(R)
    Processors may allow an authenticated user to
    potentially enable denial of service of the host system
    via local access. (CVE-2018-12207)

  - An issue was discovered in the Linux kernel before 4.20.
    There is a race condition in smp_task_timedout() and
    smp_task_done() in drivers/scsi/libsas/sas_expander.c,
    leading to a use-after-free. (CVE-2018-20836)

  - An issue was discovered in the Linux kernel before
    4.18.7. In create_qp_common in
    drivers/infiniband/hw/mlx5/qp.c, mlx5_ib_create_qp_resp
    was never initialized, resulting in a leak of stack
    memory to userspace. (CVE-2018-20855)

  - An issue was discovered in fs/xfs/xfs_super.c in the
    Linux kernel before 4.18. A use after free exists,
    related to xfs_fs_fill_super failure. (CVE-2018-20976)

  - In the tun subsystem in the Linux kernel before 4.13.14,
    dev_get_valid_name is not called before
    register_netdevice. This allows local users to cause a
    denial of service (NULL pointer dereference and panic)
    via an ioctl(TUNSETIFF) call with a dev name containing
    a / character. This is similar to CVE-2013-4343.
    (CVE-2018-7191)

  - Insufficient access control in subsystem for Intel (R)
    processor graphics in 6th, 7th, 8th and 9th Generation
    Intel(R) Core(TM) Processor Families; Intel(R)
    Pentium(R) Processor J, N, Silver and Gold Series;
    Intel(R) Celeron(R) Processor J, N, G3900 and G4900
    Series; Intel(R) Atom(R) Processor A and E3900 Series;
    Intel(R) Xeon(R) Processor E3-1500 v5 and v6 and E-2100
    Processor Families may allow an authenticated user to
    potentially enable denial of service via local access.
    (CVE-2019-0154)

  - Insufficient access control in a subsystem for Intel (R)
    processor graphics in 6th, 7th, 8th and 9th Generation
    Intel(R) Core(TM) Processor Families; Intel(R)
    Pentium(R) Processor J, N, Silver and Gold Series;
    Intel(R) Celeron(R) Processor J, N, G3900 and G4900
    Series; Intel(R) Atom(R) Processor A and E3900 Series;
    Intel(R) Xeon(R) Processor E3-1500 v5 and v6, E-2100 and
    E-2200 Processor Families; Intel(R) Graphics Driver for
    Windows before 26.20.100.6813 (DCH) or 26.20.100.6812
    and before 21.20.x.5077 (aka15.45.5077), i915 Linux
    Driver for Intel(R) Processor Graphics before versions
    5.4-rc7, 5.3.11, 4.19.84, 4.14.154, 4.9.201, 4.4.201 may
    allow an authenticated user to potentially enable
    escalation of privilege via local access.
    (CVE-2019-0155)

  - TSX Asynchronous Abort condition on some CPUs utilizing
    speculative execution may allow an authenticated user to
    potentially enable information disclosure via a side
    channel with local access. (CVE-2019-11135)

  - The Linux kernel before 5.1-rc5 allows page->_refcount
    reference count overflow, with resultant use-after-free
    issues, if about 140 GiB of RAM exists. This is related
    to fs/fuse/dev.c, fs/pipe.c, fs/splice.c,
    include/linux/mm.h, include/linux/pipe_fs_i.h,
    kernel/trace/trace.c, mm/gup.c, and mm/hugetlb.c. It can
    occur with FUSE requests. (CVE-2019-11487)

  - The do_hidp_sock_ioctl function in
    net/bluetooth/hidp/sock.c in the Linux kernel before
    5.0.15 allows a local user to obtain potentially
    sensitive information from kernel stack memory via a
    HIDPCONNADD command, because a name field may not end
    with a '\0' character. (CVE-2019-11884)

  - ** DISPUTED ** An issue was discovered in
    drm_load_edid_firmware in
    drivers/gpu/drm/drm_edid_load.c in the Linux kernel
    through 5.1.5. There is an unchecked kstrdup of fwstr,
    which might allow an attacker to cause a denial of
    service (NULL pointer dereference and system crash).
    NOTE: The vendor disputes this issues as not being a
    vulnerability because kstrdup() returning NULL is
    handled sufficiently and there is no chance for a NULL
    pointer dereference. (CVE-2019-12382)

  - An issue was discovered in the Linux kernel before
    5.2.3. There is a use-after-free caused by a malicious
    USB device in the drivers/media/usb/dvb-usb/dvb-usb-
    init.c driver. (CVE-2019-15213)

  - An issue was discovered in xfs_setattr_nonsize in
    fs/xfs/xfs_iops.c in the Linux kernel through 5.2.9. XFS
    partially wedges when a chgrp fails on account of being
    out of disk quota. xfs_setattr_nonsize is failing to
    unlock the ILOCK after the xfs_qm_vop_chown_reserve call
    fails. This is primarily a local DoS attack vector, but
    it might result as well in remote DoS if the XFS
    filesystem is exported for instance via NFS.
    (CVE-2019-15538)

  - In the Linux kernel before 5.1.13, there is a memory
    leak in drivers/scsi/libsas/sas_expander.c when SAS
    expander discovery fails. This will cause a BUG and
    denial of service. (CVE-2019-15807)

  - An issue was discovered in the Linux kernel before
    5.0.1. There is a memory leak in
    register_queue_kobjects() in net/core/net-sysfs.c, which
    will cause denial of service. (CVE-2019-15916)

  - An issue was discovered in the Linux kernel before
    5.0.4. The 9p filesystem did not protect i_size_write()
    properly, which causes an i_size_read() infinite loop
    and denial of service on SMP systems. (CVE-2019-16413)

  - An issue was discovered in write_tpt_entry in
    drivers/infiniband/hw/cxgb4/mem.c in the Linux kernel
    through 5.3.2. The cxgb4 driver is directly calling
    dma_map_single (a DMA function) from a stack variable.
    This could allow an attacker to trigger a Denial of
    Service, exploitable if this driver is used on an
    architecture for which this stack/DMA interaction has
    security relevance. (CVE-2019-17075)

  - The SCTP socket buffer used by a userspace application
    is not accounted by the cgroups subsystem. An attacker
    can use this flaw to cause a denial of service attack.
    Kernel 3.10.x and 4.18.x branches are believed to be
    vulnerable. (CVE-2019-3874)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0266");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel-rt packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20836");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "kernel-rt-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-debug-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-debug-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-debug-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-debug-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-debug-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-debuginfo-common-x86_64-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-doc-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-trace-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-trace-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-trace-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-trace-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-trace-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1"
  ],
  "CGSL MAIN 5.04": [
    "kernel-rt-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-debug-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-debug-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-debug-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-debug-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-debug-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-debuginfo-common-x86_64-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-doc-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-trace-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-trace-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-trace-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-trace-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1",
    "kernel-rt-trace-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.28.389.gdaa53e1"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-rt");
}
