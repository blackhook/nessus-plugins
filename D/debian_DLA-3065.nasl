#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3065. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(162697);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/26");

  script_cve_id(
    "CVE-2018-1108",
    "CVE-2021-4149",
    "CVE-2021-39713",
    "CVE-2022-0494",
    "CVE-2022-0812",
    "CVE-2022-0854",
    "CVE-2022-1011",
    "CVE-2022-1012",
    "CVE-2022-1016",
    "CVE-2022-1198",
    "CVE-2022-1199",
    "CVE-2022-1353",
    "CVE-2022-1516",
    "CVE-2022-1729",
    "CVE-2022-1734",
    "CVE-2022-1974",
    "CVE-2022-1975",
    "CVE-2022-2153",
    "CVE-2022-21123",
    "CVE-2022-21125",
    "CVE-2022-21166",
    "CVE-2022-23036",
    "CVE-2022-23037",
    "CVE-2022-23038",
    "CVE-2022-23039",
    "CVE-2022-23040",
    "CVE-2022-23041",
    "CVE-2022-23042",
    "CVE-2022-23960",
    "CVE-2022-24958",
    "CVE-2022-26490",
    "CVE-2022-26966",
    "CVE-2022-27223",
    "CVE-2022-28356",
    "CVE-2022-28390",
    "CVE-2022-30594",
    "CVE-2022-32250",
    "CVE-2022-32296",
    "CVE-2022-33981"
  );

  script_name(english:"Debian DLA-3065-1 : linux - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3065 advisory.

  - kernel drivers before version 4.17-rc1 are vulnerable to a weakness in the Linux kernel's implementation
    of random seed data. Programs, early in the boot sequence, could use the data allocated for the seed
    before it was sufficiently generated. (CVE-2018-1108)

  - Product: AndroidVersions: Android kernelAndroid ID: A-173788806References: Upstream kernel
    (CVE-2021-39713)

  - A vulnerability was found in btrfs_alloc_tree_b in fs/btrfs/extent-tree.c in the Linux kernel due to an
    improper lock operation in btrfs. In this flaw, a user with a local privilege may cause a denial of
    service (DOS) due to a deadlock problem. (CVE-2021-4149)

  - A kernel information leak flaw was identified in the scsi_ioctl function in drivers/scsi/scsi_ioctl.c in
    the Linux kernel. This flaw allows a local attacker with a special user privilege (CAP_SYS_ADMIN or
    CAP_SYS_RAWIO) to create issues with confidentiality. (CVE-2022-0494)

  - A memory leak flaw was found in the Linux kernel's DMA subsystem, in the way a user calls DMA_FROM_DEVICE.
    This flaw allows a local user to read random memory from the kernel space. (CVE-2022-0854)

  - A use-after-free flaw was found in the Linux kernel's FUSE filesystem in the way a user triggers write().
    This flaw allows a local user to gain unauthorized access to data from the FUSE filesystem, resulting in
    privilege escalation. (CVE-2022-1011)

  - A vulnerability was found in the pfkey_register function in net/key/af_key.c in the Linux kernel. This
    flaw allows a local, unprivileged user to gain access to kernel memory, leading to a system crash or a
    leak of internal kernel information. (CVE-2022-1353)

  - A NULL pointer dereference flaw was found in the Linux kernel's X.25 set of standardized network protocols
    functionality in the way a user terminates their session using a simulated Ethernet card and continued
    usage of this connection. This flaw allows a local user to crash the system. (CVE-2022-1516)

  - A flaw in Linux Kernel found in nfcmrvl_nci_unregister_dev() in drivers/nfc/nfcmrvl/main.c can lead to use
    after free both read or write when non synchronized between cleanup routine and firmware download routine.
    (CVE-2022-1734)

  - Incomplete cleanup of multi-core shared buffers for some Intel(R) Processors may allow an authenticated
    user to potentially enable information disclosure via local access. (CVE-2022-21123)

  - Incomplete cleanup of microarchitectural fill buffers on some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21125)

  - Incomplete cleanup in specific special register write operations for some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21166)

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

  - Certain Arm Cortex and Neoverse processors through 2022-03-08 do not properly restrict cache speculation,
    aka Spectre-BHB. An attacker can leverage the shared branch history in the Branch History Buffer (BHB) to
    influence mispredicted branches. Then, cache allocation can allow the attacker to obtain sensitive
    information. (CVE-2022-23960)

  - drivers/usb/gadget/legacy/inode.c in the Linux kernel through 5.16.8 mishandles dev->buf release.
    (CVE-2022-24958)

  - st21nfca_connectivity_event_received in drivers/nfc/st21nfca/se.c in the Linux kernel through 5.16.12 has
    EVT_TRANSACTION buffer overflows because of untrusted length parameters. (CVE-2022-26490)

  - An issue was discovered in the Linux kernel before 5.16.12. drivers/net/usb/sr9700.c allows attackers to
    obtain sensitive information from heap memory via crafted frame lengths from a device. (CVE-2022-26966)

  - In drivers/usb/gadget/udc/udc-xilinx.c in the Linux kernel before 5.16.12, the endpoint index is not
    validated and might be manipulated by the host for out-of-array access. (CVE-2022-27223)

  - In the Linux kernel before 5.17.1, a refcount leak bug was found in net/llc/af_llc.c. (CVE-2022-28356)

  - ems_usb_start_xmit in drivers/net/can/usb/ems_usb.c in the Linux kernel through 5.17.1 has a double free.
    (CVE-2022-28390)

  - The Linux kernel before 5.17.2 mishandles seccomp permissions. The PTRACE_SEIZE code path allows attackers
    to bypass intended restrictions on setting the PT_SUSPEND_SECCOMP flag. (CVE-2022-30594)

  - net/netfilter/nf_tables_api.c in the Linux kernel through 5.18.1 allows a local user (able to create
    user/net namespaces) to escalate privileges to root because an incorrect NFT_STATEFUL_EXPR check leads to
    a use-after-free. (CVE-2022-32250)

  - The Linux kernel before 5.17.9 allows TCP servers to identify clients by observing what source ports are
    used. (CVE-2022-32296)

  - drivers/block/floppy.c in the Linux kernel before 5.17.6 is vulnerable to a denial of service, because of
    a concurrency use-after-free flaw after deallocating raw_cmd in the raw_cmd_ioctl function.
    (CVE-2022-33981)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=922204");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3065");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-1108");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39713");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4149");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0494");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0812");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0854");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1011");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1012");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1016");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1198");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1199");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1353");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1516");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1729");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1734");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1974");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1975");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21123");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21125");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21166");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2153");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23036");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23037");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23038");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23039");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23040");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23041");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23042");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23960");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24958");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26490");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26966");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27223");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28356");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28390");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30594");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32250");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32296");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33981");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux packages.

For Debian 9 stretch, these problems have been fixed in version 4.9.320-2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32250");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-27223");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libusbip-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-6-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-6-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-18-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-18-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-manual-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.9.0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'hyperv-daemons', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'libcpupower-dev', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'libcpupower1', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'libusbip-dev', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-compiler-gcc-6-arm', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-compiler-gcc-6-x86', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-cpupower', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-doc-4.9', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-686', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-686-pae', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-all', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-all-amd64', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-all-arm64', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-all-armel', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-all-armhf', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-all-i386', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-amd64', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-arm64', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-armmp', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-armmp-lpae', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-common', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-common-rt', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-marvell', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-rt-686-pae', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-18-rt-amd64', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-686', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-686-dbg', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-686-pae', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-686-pae-dbg', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-amd64', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-amd64-dbg', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-arm64', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-arm64-dbg', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-armmp', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-armmp-dbg', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-armmp-lpae', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-armmp-lpae-dbg', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-marvell', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-marvell-dbg', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-rt-686-pae', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-rt-686-pae-dbg', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-rt-amd64', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-18-rt-amd64-dbg', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-kbuild-4.9', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-libc-dev', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-manual-4.9', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-perf-4.9', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-source-4.9', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'linux-support-4.9.0-18', 'reference': '4.9.320-2'},
    {'release': '9.0', 'prefix': 'usbip', 'reference': '4.9.320-2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hyperv-daemons / libcpupower-dev / libcpupower1 / libusbip-dev / etc');
}
