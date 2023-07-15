#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151167);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2018-12928",
    "CVE-2018-12929",
    "CVE-2021-0342",
    "CVE-2021-3178",
    "CVE-2021-3347",
    "CVE-2021-3348",
    "CVE-2021-20177",
    "CVE-2021-20292",
    "CVE-2021-27363",
    "CVE-2021-27364",
    "CVE-2021-27365",
    "CVE-2021-28660"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : kernel (EulerOS-SA-2021-2002)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - A flaw was found in the Linux kernel's implementation
    of string matching within a packet. A privileged user
    (with root or CAP_NET_ADMIN) when inserting iptables
    rules could insert a rule which can panic the
    system.(CVE-2021-20177)

  - rtw_wx_set_scan in
    drivers/staging/rtl8188eu/os_dep/ioctl_linux.c in the
    Linux kernel through 5.11.6 allows writing beyond the
    end of the ->ssid[] array. NOTE: from the perspective
    of kernel.org releases, CVE IDs are not normally used
    for drivers/staging/* (unfinished work) however, system
    integrators may have situations in which a
    drivers/staging issue is relevant to their own customer
    base.(CVE-2021-28660)

  - There is a flaw reported in
    drivers/gpu/drm/nouveau/nouveau_sgdma.c in
    nouveau_sgdma_create_ttm in Nouveau DRM subsystem. The
    issue results from the lack of validating the existence
    of an object prior to performing operations on the
    object. An attacker with a local account with a root
    privilege, can leverage this vulnerability to escalate
    privileges and execute code in the context of the
    kernel.(CVE-2021-20292)

  - ntfs_read_locked_inode in the ntfs.ko filesystem driver
    in the Linux kernel 4.15.0 allows attackers to trigger
    a use-after-free read and possibly cause a denial of
    service (kernel oops or panic) via a crafted ntfs
    filesystem.(CVE-2018-12929)

  - In the Linux kernel 4.15.0, a NULL pointer dereference
    was discovered in hfs_ext_read_extent in hfs.ko. This
    can occur during a mount of a crafted hfs
    filesystem.(CVE-2018-12928)

  - An issue was discovered in the Linux kernel through
    5.11.3. A kernel pointer leak can be used to determine
    the address of the iscsi_transport structure. When an
    iSCSI transport is registered with the iSCSI subsystem,
    the transport's handle is available to unprivileged
    users via the sysfs file system, at
    /sys/class/iscsi_transport/$TRANSPORT_NAME/handle. When
    read, the show_transport_handle function (in
    drivers/scsi/scsi_transport_iscsi.c) is called, which
    leaks the handle. This handle is actually the pointer
    to an iscsi_transport struct in the kernel module's
    global variables.(CVE-2021-27363)

  - An issue was discovered in the Linux kernel through
    5.11.3. drivers/scsi/scsi_transport_iscsi.c is
    adversely affected by the ability of an unprivileged
    user to craft Netlink messages.(CVE-2021-27364)

  - An issue was discovered in the Linux kernel through
    5.11.3. Certain iSCSI data structures do not have
    appropriate length constraints or checks, and can
    exceed the PAGE_SIZE value. An unprivileged user can
    send a Netlink message that is associated with iSCSI,
    and has a length up to the maximum length of a Netlink
    message.(CVE-2021-27365)

  - nbd_add_socket in drivers/block/nbd.c in the Linux
    kernel through 5.10.12 has an ndb_queue_rq
    use-after-free that could be triggered by local
    attackers (with access to the nbd device) via an I/O
    request at a certain point during device setup, aka
    CID-b98e762e3d71.(CVE-2021-3348)

  - An issue was discovered in the Linux kernel through
    5.10.11. PI futexes have a kernel stack use-after-free
    during fault handling, allowing local users to execute
    code in the kernel, aka
    CID-34b1a1ce1458.(CVE-2021-3347)

  - fs/nfsd/nfs3xdr.c in the Linux kernel through 5.10.8,
    when there is an NFS export of a subdirectory of a
    filesystem, allows remote attackers to traverse to
    other parts of the filesystem via READDIRPLUS. NOTE:
    some parties argue that such a subdirectory export is
    not intended to prevent this attack see also the
    exports(5) no_subtree_check default
    behavior.(CVE-2021-3178)

  - In tun_get_user of tun.c, there is possible memory
    corruption due to a use after free. This could lead to
    local escalation of privilege with System execution
    privileges required. User interaction is not required
    for exploitation.(CVE-2021-0342)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e79e4b6");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["bpftool-4.19.36-vhulk1907.1.0.h1017.eulerosv2r8",
        "kernel-4.19.36-vhulk1907.1.0.h1017.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h1017.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h1017.eulerosv2r8",
        "kernel-source-4.19.36-vhulk1907.1.0.h1017.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h1017.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h1017.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h1017.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h1017.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h1017.eulerosv2r8"];

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
