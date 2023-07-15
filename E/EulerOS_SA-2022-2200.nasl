##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163617);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2021-3772",
    "CVE-2021-26930",
    "CVE-2021-28688",
    "CVE-2021-28972",
    "CVE-2021-38300",
    "CVE-2021-39633",
    "CVE-2021-39698",
    "CVE-2021-45486",
    "CVE-2021-45868",
    "CVE-2022-0492",
    "CVE-2022-0617",
    "CVE-2022-1011",
    "CVE-2022-1016",
    "CVE-2022-1055",
    "CVE-2022-1199",
    "CVE-2022-1204",
    "CVE-2022-1205",
    "CVE-2022-24448",
    "CVE-2022-24958",
    "CVE-2022-25375",
    "CVE-2022-26966",
    "CVE-2022-27223",
    "CVE-2022-27666"
  );

  script_name(english:"EulerOS Virtualization 2.9.0 : kernel (EulerOS-SA-2022-2200)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - An issue was discovered in the Linux kernel 3.11 through 5.10.16, as used by Xen. To service requests to
    the PV backend, the driver maps grant references provided by the frontend. In this process, errors may be
    encountered. In one case, an error encountered earlier might be discarded by later processing, resulting
    in the caller assuming successful mapping, and hence subsequent operations trying to access space that
    wasn't mapped. In another case, internal state would be insufficiently updated, preventing safe recovery
    from the error. This affects drivers/block/xen-blkback/blkback.c. (CVE-2021-26930)

  - The fix for XSA-365 includes initialization of pointers such that subsequent cleanup code wouldn't use
    uninitialized or stale values. This initialization went too far and may under certain conditions also
    overwrite pointers which are in need of cleaning up. The lack of cleanup would result in leaking
    persistent grants. The leak in turn would prevent fully cleaning up after a respective guest has died,
    leaving around zombie domains. All Linux versions having the fix for XSA-365 applied are vulnerable.
    XSA-365 was classified to affect versions back to at least 3.11. (CVE-2021-28688)

  - In drivers/pci/hotplug/rpadlpar_sysfs.c in the Linux kernel through 5.11.8, the RPA PCI Hotplug driver has
    a user-tolerable buffer overflow when writing a new device name to the driver from userspace, allowing
    userspace to write data to the kernel stack frame directly. This occurs because add_slot_store and
    remove_slot_store mishandle drc_name '\0' termination, aka CID-cc7a0bb058b8. (CVE-2021-28972)

  - A flaw was found in the Linux SCTP stack. A blind attacker may be able to kill an existing SCTP
    association through invalid chunks if the attacker knows the IP-addresses and port numbers being used and
    the attacker can send packets with spoofed IP addresses. (CVE-2021-3772)

  - arch/mips/net/bpf_jit.c in the Linux kernel before 5.4.10 can generate undesirable machine code when
    transforming unprivileged cBPF programs, allowing execution of arbitrary code within the kernel context.
    This occurs because conditional branches can exceed the 128 KB limit of the MIPS architecture.
    (CVE-2021-38300)

  - In gre_handle_offloads of ip_gre.c, there is a possible page fault due to an invalid memory access. This
    could lead to local information disclosure with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-150694665References: Upstream kernel (CVE-2021-39633)

  - In aio_poll_complete_work of aio.c, there is a possible memory corruption due to a use after free. This
    could lead to local escalation of privilege with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-185125206References: Upstream kernel (CVE-2021-39698)

  - In the IPv4 implementation in the Linux kernel before 5.12.4, net/ipv4/route.c has an information leak
    because the hash table is very small. (CVE-2021-45486)

  - In the Linux kernel before 5.15.3, fs/quota/quota_tree.c does not validate the block number in the quota
    tree (on disk). This can, for example, lead to a kernel/locking/rwsem.c use-after-free if there is a
    corrupted quota file. (CVE-2021-45868)

  - A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the
    kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups
    v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.
    (CVE-2022-0492)

  - A flaw null pointer dereference in the Linux kernel UDF file system functionality was found in the way
    user triggers udf_file_write_iter function for the malicious UDF image. A local user could use this flaw
    to crash the system. Actual from Linux kernel 4.2-rc1 till 5.17-rc2. (CVE-2022-0617)

  - A use-after-free flaw was found in the Linux kernel's FUSE filesystem in the way a user triggers write().
    This flaw allows a local user to gain unauthorized access to data from the FUSE filesystem, resulting in
    privilege escalation. (CVE-2022-1011)

  - A use-after-free exists in the Linux Kernel in tc_new_tfilter that could allow a local attacker to gain
    privilege escalation. The exploit requires unprivileged user namespaces. We recommend upgrading past
    commit 04c2a47ffb13c29778e2a14e414ad4cb5a5db4b5 (CVE-2022-1055)

  - An issue was discovered in fs/nfs/dir.c in the Linux kernel before 5.16.5. If an application sets the
    O_DIRECTORY flag, and tries to open a regular file, nfs_atomic_open() performs a regular lookup. If a
    regular file is found, ENOTDIR should occur, but the server instead returns uninitialized data in the file
    descriptor. (CVE-2022-24448)

  - drivers/usb/gadget/legacy/inode.c in the Linux kernel through 5.16.8 mishandles dev->buf release.
    (CVE-2022-24958)

  - An issue was discovered in drivers/usb/gadget/function/rndis.c in the Linux kernel before 5.16.10. The
    RNDIS USB gadget lacks validation of the size of the RNDIS_MSG_SET command. Attackers can obtain sensitive
    information from kernel memory. (CVE-2022-25375)

  - An issue was discovered in the Linux kernel before 5.16.12. drivers/net/usb/sr9700.c allows attackers to
    obtain sensitive information from heap memory via crafted frame lengths from a device. (CVE-2022-26966)

  - In drivers/usb/gadget/udc/udc-xilinx.c in the Linux kernel before 5.16.12, the endpoint index is not
    validated and might be manipulated by the host for out-of-array access. (CVE-2022-27223)

  - A heap buffer overflow flaw was found in IPsec ESP transformation code in net/ipv4/esp4.c and
    net/ipv6/esp6.c. This flaw allows a local attacker with a normal user privilege to overwrite kernel heap
    objects and may cause a local privilege escalation threat. (CVE-2022-27666)

  - A flaw was found in the Linux kernel in net/netfilter/nf_tables_core.c:nft_do_chain,which can cause a use-
    after-free.This issue needs to handle return with proper preconditions,as it can lead to a kernel
    information leak problem caused by a local,unprivileged attacker. (CVE-2022-1016)

  - kernel: Null pointer dereference and use after free in ax25_release() (CVE-2022-1199)

  - A use-after-free flaw was found in the Linux kernel's Amateur Radio AX.25 protocol functionality in the
    way a user connects with the protocol. This flaw allows a local user to crash the system. (CVE-2022-1204)

  - A NULL pointer dereference flaw was found in the Linux kernel's Amateur Radio AX.25 protocol functionality
    in the way a user connects with the protocol. This flaw allows a local user to crash the system.
    (CVE-2022-1205)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2200
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f8fc20a");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39698");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-27223");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.9.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.18.0-147.5.1.6.h729.eulerosv2r9",
  "kernel-tools-4.18.0-147.5.1.6.h729.eulerosv2r9",
  "kernel-tools-libs-4.18.0-147.5.1.6.h729.eulerosv2r9",
  "python3-perf-4.18.0-147.5.1.6.h729.eulerosv2r9"
];

foreach (var pkg in pkgs)
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
