##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2022-129-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160874);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/13");

  script_cve_id(
    "CVE-2022-0001",
    "CVE-2022-0002",
    "CVE-2022-0168",
    "CVE-2022-0494",
    "CVE-2022-0500",
    "CVE-2022-0742",
    "CVE-2022-0854",
    "CVE-2022-0995",
    "CVE-2022-1011",
    "CVE-2022-1015",
    "CVE-2022-1016",
    "CVE-2022-1048",
    "CVE-2022-1158",
    "CVE-2022-1198",
    "CVE-2022-1199",
    "CVE-2022-1204",
    "CVE-2022-1205",
    "CVE-2022-1263",
    "CVE-2022-1353",
    "CVE-2022-1516",
    "CVE-2022-23036",
    "CVE-2022-23037",
    "CVE-2022-23038",
    "CVE-2022-23039",
    "CVE-2022-23040",
    "CVE-2022-23041",
    "CVE-2022-23042",
    "CVE-2022-23222",
    "CVE-2022-23960",
    "CVE-2022-24958",
    "CVE-2022-26490",
    "CVE-2022-27666",
    "CVE-2022-28356",
    "CVE-2022-28388",
    "CVE-2022-28389",
    "CVE-2022-28390",
    "CVE-2022-29582"
  );

  script_name(english:"Slackware Linux 15.0 kernel-generic  Multiple Vulnerabilities (SSA:2022-129-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to kernel-generic.");
  script_set_attribute(attribute:"description", value:
"The version of kernel-generic installed on the remote host is prior to 5.15.38 / 5.15.38_smp. It is, therefore, affected
by multiple vulnerabilities as referenced in the SSA:2022-129-01 advisory.

  - Non-transparent sharing of branch predictor selectors between contexts in some Intel(R) Processors may
    allow an authorized user to potentially enable information disclosure via local access. (CVE-2022-0001)

  - Non-transparent sharing of branch predictor within a context in some Intel(R) Processors may allow an
    authorized user to potentially enable information disclosure via local access. (CVE-2022-0002)

  - A kernel information leak flaw was identified in the scsi_ioctl function in drivers/scsi/scsi_ioctl.c in
    the Linux kernel. This flaw allows a local attacker with a special user privilege (CAP_SYS_ADMIN or
    CAP_SYS_RAWIO) to create issues with confidentiality. (CVE-2022-0494)

  - A flaw was found in unrestricted eBPF usage by the BPF_BTF_LOAD, leading to a possible out-of-bounds
    memory write in the Linux kernel's BPF subsystem due to the way a user loads BTF. This flaw allows a local
    user to crash or escalate their privileges on the system. (CVE-2022-0500)

  - Memory leak in icmp6 implementation in Linux Kernel 5.13+ allows a remote attacker to DoS a host by making
    it go out-of-memory via icmp6 packets of type 130 or 131. We recommend upgrading past commit
    2d3916f3189172d5c69d33065c3c21119fe539fc. (CVE-2022-0742)

  - A memory leak flaw was found in the Linux kernel's DMA subsystem, in the way a user calls DMA_FROM_DEVICE.
    This flaw allows a local user to read random memory from the kernel space. (CVE-2022-0854)

  - An out-of-bounds (OOB) memory write flaw was found in the Linux kernel's watch_queue event notification
    subsystem. This flaw can overwrite parts of the kernel state, potentially allowing a local user to gain
    privileged access or cause a denial of service on the system. (CVE-2022-0995)

  - A use-after-free flaw was found in the Linux kernel's FUSE filesystem in the way a user triggers write().
    This flaw allows a local user to gain unauthorized access to data from the FUSE filesystem, resulting in
    privilege escalation. (CVE-2022-1011)

  - A flaw was found in the Linux kernel in linux/net/netfilter/nf_tables_api.c of the netfilter subsystem.
    This flaw allows a local user to cause an out-of-bounds write issue. (CVE-2022-1015)

  - A use-after-free flaw was found in the Linux kernel's sound subsystem in the way a user triggers
    concurrent calls of PCM hw_params. The hw_free ioctls or similar race condition happens inside ALSA PCM
    for other ioctls. This flaw allows a local user to crash or potentially escalate their privileges on the
    system. (CVE-2022-1048)

  - A vulnerability was found in the pfkey_register function in net/key/af_key.c in the Linux kernel. This
    flaw allows a local, unprivileged user to gain access to kernel memory, leading to a system crash or a
    leak of internal kernel information. (CVE-2022-1353)

  - A NULL pointer dereference flaw was found in the Linux kernel's X.25 set of standardized network protocols
    functionality in the way a user terminates their session using a simulated Ethernet card and continued
    usage of this connection. This flaw allows a local user to crash the system. (CVE-2022-1516)

  - Linux PV device frontends vulnerable to attacks by backends T[his CNA information record relates to
    multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Several Linux PV
    device frontends are using the grant table interfaces for removing access rights of the backends in ways
    being subject to race conditions, resulting in potential data leaks, data corruption by malicious
    backends, and denial of service triggered by malicious backends: blkfront, netfront, scsifront and the
    gntalloc driver are testing whether a grant reference is still in use. If this is not the case, they
    assume that a following removal of the granted access will always succeed, which is not true in case the
    backend has mapped the granted page between those two operations. As a result the backend can keep access
    to the memory page of the guest no matter how the page will be used after the frontend I/O has finished.
    The xenbus driver has a similar problem, as it doesn't check the success of removing the granted access of
    a shared ring buffer. blkfront: CVE-2022-23036 netfront: CVE-2022-23037 scsifront: CVE-2022-23038
    gntalloc: CVE-2022-23039 xenbus: CVE-2022-23040 blkfront, netfront, scsifront, usbfront, dmabuf, xenbus,
    9p, kbdfront, and pvcalls are using a functionality to delay freeing a grant reference until it is no
    longer in use, but the freeing of the related data page is not synchronized with dropping the granted
    access. As a result the backend can keep access to the memory page even after it has been freed and then
    re-used for a different purpose. CVE-2022-23041 netfront will fail a BUG_ON() assertion if it fails to
    revoke access in the rx path. This will result in a Denial of Service (DoS) situation of the guest which
    can be triggered by the backend. CVE-2022-23042 (CVE-2022-23036, CVE-2022-23037, CVE-2022-23038,
    CVE-2022-23039, CVE-2022-23040, CVE-2022-23041, CVE-2022-23042)

  - kernel/bpf/verifier.c in the Linux kernel through 5.15.14 allows local users to gain privileges because of
    the availability of pointer arithmetic via certain *_OR_NULL pointer types. (CVE-2022-23222)

  - Certain Arm Cortex and Neoverse processors through 2022-03-08 do not properly restrict cache speculation,
    aka Spectre-BHB. An attacker can leverage the shared branch history in the Branch History Buffer (BHB) to
    influence mispredicted branches. Then, cache allocation can allow the attacker to obtain sensitive
    information. (CVE-2022-23960)

  - drivers/usb/gadget/legacy/inode.c in the Linux kernel through 5.16.8 mishandles dev->buf release.
    (CVE-2022-24958)

  - st21nfca_connectivity_event_received in drivers/nfc/st21nfca/se.c in the Linux kernel through 5.16.12 has
    EVT_TRANSACTION buffer overflows because of untrusted length parameters. (CVE-2022-26490)

  - A heap buffer overflow flaw was found in IPsec ESP transformation code in net/ipv4/esp4.c and
    net/ipv6/esp6.c. This flaw allows a local attacker with a normal user privilege to overwrite kernel heap
    objects and may cause a local privilege escalation threat. (CVE-2022-27666)

  - In the Linux kernel before 5.17.1, a refcount leak bug was found in net/llc/af_llc.c. (CVE-2022-28356)

  - usb_8dev_start_xmit in drivers/net/can/usb/usb_8dev.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28388)

  - mcba_usb_start_xmit in drivers/net/can/usb/mcba_usb.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28389)

  - ems_usb_start_xmit in drivers/net/can/usb/ems_usb.c in the Linux kernel through 5.17.1 has a double free.
    (CVE-2022-28390)

  - In the Linux kernel before 5.17.3, fs/io_uring.c has a use-after-free due to a race condition in io_uring
    timeouts. This can be triggered by a local user who has no access to any user namespace; however, the race
    condition perhaps can only be exploited infrequently. (CVE-2022-29582)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected kernel-generic package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23222");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28390");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Watch Queue Out of Bounds Write');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '5.15.38', 'product' : 'kernel-generic', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '5.15.38', 'product' : 'kernel-huge', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '5.15.38', 'product' : 'kernel-modules', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '5.15.38_smp', 'product' : 'kernel-generic-smp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '5.15.38_smp', 'product' : 'kernel-huge-smp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '5.15.38_smp', 'product' : 'kernel-modules-smp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '5.15.38', 'product' : 'kernel-source', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'noarch' },
    { 'fixed_version' : '5.15.38_smp', 'product' : 'kernel-source', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'noarch' },
    { 'fixed_version' : '5.15.38', 'product' : 'kernel-headers', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86' },
    { 'fixed_version' : '5.15.38_smp', 'product' : 'kernel-headers', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86' },
    { 'fixed_version' : '5.15.38', 'product' : 'kernel-generic', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '5.15.38', 'product' : 'kernel-huge', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '5.15.38', 'product' : 'kernel-modules', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86_64' }
];

foreach constraint (constraints) {
    var pkg_arch = constraint['arch'];
    var arch = NULL;
    if (pkg_arch == "x86_64") {
        arch = pkg_arch;
    }
    if (slackware_check(osver:constraint['os_version'],
                        arch:arch,
                        pkgname:constraint['product'],
                        pkgver:constraint['fixed_version'],
                        pkgarch:pkg_arch,
                        pkgnum:constraint['service_pack'])) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
