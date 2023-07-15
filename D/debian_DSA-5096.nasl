#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5096. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158761);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-29374",
    "CVE-2020-36322",
    "CVE-2021-3640",
    "CVE-2021-3744",
    "CVE-2021-3752",
    "CVE-2021-3760",
    "CVE-2021-3764",
    "CVE-2021-3772",
    "CVE-2021-4002",
    "CVE-2021-4083",
    "CVE-2021-4135",
    "CVE-2021-4155",
    "CVE-2021-4202",
    "CVE-2021-4203",
    "CVE-2021-20317",
    "CVE-2021-20321",
    "CVE-2021-20322",
    "CVE-2021-22600",
    "CVE-2021-28711",
    "CVE-2021-28712",
    "CVE-2021-28713",
    "CVE-2021-28714",
    "CVE-2021-28715",
    "CVE-2021-28950",
    "CVE-2021-38300",
    "CVE-2021-39685",
    "CVE-2021-39686",
    "CVE-2021-39698",
    "CVE-2021-39713",
    "CVE-2021-41864",
    "CVE-2021-42739",
    "CVE-2021-43389",
    "CVE-2021-43975",
    "CVE-2021-43976",
    "CVE-2021-44733",
    "CVE-2021-45095",
    "CVE-2021-45469",
    "CVE-2021-45480",
    "CVE-2022-0001",
    "CVE-2022-0002",
    "CVE-2022-0322",
    "CVE-2022-0330",
    "CVE-2022-0435",
    "CVE-2022-0487",
    "CVE-2022-0492",
    "CVE-2022-0617",
    "CVE-2022-0644",
    "CVE-2022-22942",
    "CVE-2022-24448",
    "CVE-2022-24959",
    "CVE-2022-25258",
    "CVE-2022-25375"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/02");

  script_name(english:"Debian DSA-5096-1 : linux - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5096 advisory.

  - An issue was discovered in the Linux kernel before 5.7.3, related to mm/gup.c and mm/huge_memory.c. The
    get_user_pages (aka gup) implementation, when used for a copy-on-write page, does not properly consider
    the semantics of read operations and therefore can grant unintended write access, aka CID-17839856fd58.
    (CVE-2020-29374)

  - An issue was discovered in the FUSE filesystem implementation in the Linux kernel before 5.10.6, aka
    CID-5d069dbe8aaf. fuse_do_getattr() calls make_bad_inode() in inappropriate situations, causing a system
    crash. NOTE: the original fix for this vulnerability was incomplete, and its incompleteness is tracked as
    CVE-2021-28950. (CVE-2020-36322)

  - A flaw was found in the Linux kernel. A corrupted timer tree caused the task wakeup to be missing in the
    timerqueue_add function in lib/timerqueue.c. This flaw allows a local attacker with special user
    privileges to cause a denial of service, slowing and eventually stopping the system while running OSP.
    (CVE-2021-20317)

  - A race condition accessing file object in the Linux kernel OverlayFS subsystem was found in the way users
    do rename in specific way with OverlayFS. A local user could use this flaw to crash the system.
    (CVE-2021-20321)

  - A flaw in the processing of received ICMP errors (ICMP fragment needed and ICMP redirect) in the Linux
    kernel functionality was found to allow the ability to quickly scan open UDP ports. This flaw allows an
    off-path remote user to effectively bypass the source port UDP randomization. The highest threat from this
    vulnerability is to confidentiality and possibly integrity, because software that relies on UDP source
    port randomization are indirectly affected as well. (CVE-2021-20322)

  - A double free bug in packet_set_ring() in net/packet/af_packet.c can be exploited by a local user through
    crafted syscalls to escalate privileges or deny service. We recommend upgrading kernel past the effected
    versions or rebuilding past ec6af094ea28f0f2dda1a6a33b14cd57e36a9755 (CVE-2021-22600)

  - Rogue backends can cause DoS of guests via high frequency events T[his CNA information record relates to
    multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Xen offers the
    ability to run PV backends in regular unprivileged guests, typically referred to as driver domains.
    Running PV backends in driver domains has one primary security advantage: if a driver domain gets
    compromised, it doesn't have the privileges to take over the system. However, a malicious driver domain
    could try to attack other guests via sending events at a high frequency leading to a Denial of Service in
    the guest due to trying to service interrupts for elongated amounts of time. There are three affected
    backends: * blkfront patch 1, CVE-2021-28711 * netfront patch 2, CVE-2021-28712 * hvc_xen (console) patch
    3, CVE-2021-28713 (CVE-2021-28711, CVE-2021-28712, CVE-2021-28713)

  - Guest can force Linux netback driver to hog large amounts of kernel memory T[his CNA information record
    relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.]
    Incoming data packets for a guest in the Linux kernel's netback driver are buffered until the guest is
    ready to process them. There are some measures taken for avoiding to pile up too much data, but those can
    be bypassed by the guest: There is a timeout how long the client side of an interface can stop consuming
    new packets before it is assumed to have stalled, but this timeout is rather long (60 seconds by default).
    Using a UDP connection on a fast interface can easily accumulate gigabytes of data in that time.
    (CVE-2021-28715) The timeout could even never trigger if the guest manages to have only one free slot in
    its RX queue ring page and the next package would require more than one free slot, which may be the case
    when using GSO, XDP, or software hashing. (CVE-2021-28714) (CVE-2021-28714, CVE-2021-28715)

  - An issue was discovered in fs/fuse/fuse_i.h in the Linux kernel before 5.11.8. A stall on CPU can occur
    because a retry loop continually finds the same bad inode, aka CID-775c5033a0d1. (CVE-2021-28950)

  - A flaw use-after-free in function sco_sock_sendmsg() of the Linux kernel HCI subsystem was found in the
    way user calls ioct UFFDIO_REGISTER or other way triggers race condition of the call sco_conn_del()
    together with the call sco_sock_sendmsg() with the expected controllable faulting memory page. A
    privileged local user could use this flaw to crash the system or escalate their privileges on the system.
    (CVE-2021-3640)

  - A memory leak flaw was found in the Linux kernel in the ccp_run_aes_gcm_cmd() function in
    drivers/crypto/ccp/ccp-ops.c, which allows attackers to cause a denial of service (memory consumption).
    This vulnerability is similar with the older CVE-2019-18808. (CVE-2021-3744)

  - A use-after-free flaw was found in the Linux kernel's Bluetooth subsystem in the way user calls connect to
    the socket and disconnect simultaneously due to a race condition. This flaw allows a user to crash the
    system or escalate their privileges. The highest threat from this vulnerability is to confidentiality,
    integrity, as well as system availability. (CVE-2021-3752)

  - A flaw was found in the Linux kernel. A use-after-free vulnerability in the NFC stack can lead to a threat
    to confidentiality, integrity, and system availability. (CVE-2021-3760)

  - A flaw was found in the Linux SCTP stack. A blind attacker may be able to kill an existing SCTP
    association through invalid chunks if the attacker knows the IP-addresses and port numbers being used and
    the attacker can send packets with spoofed IP addresses. (CVE-2021-3772)

  - arch/mips/net/bpf_jit.c in the Linux kernel before 5.4.10 can generate undesirable machine code when
    transforming unprivileged cBPF programs, allowing execution of arbitrary code within the kernel context.
    This occurs because conditional branches can exceed the 128 KB limit of the MIPS architecture.
    (CVE-2021-38300)

  - A memory leak flaw in the Linux kernel's hugetlbfs memory usage was found in the way the user maps some
    regions of memory twice using shmget() which are aligned to PUD alignment with the fault of some of the
    memory pages. A local user could use this flaw to get unauthorized access to some data. (CVE-2021-4002)

  - A read-after-free memory flaw was found in the Linux kernel's garbage collection for Unix domain socket
    file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race
    condition. This flaw allows a local user to crash the system or escalate their privileges on the system.
    This flaw affects Linux kernel versions prior to 5.16-rc4. (CVE-2021-4083)

  - prealloc_elems_and_freelist in kernel/bpf/stackmap.c in the Linux kernel before 5.14.12 allows
    unprivileged users to trigger an eBPF multiplication integer overflow with a resultant out-of-bounds
    write. (CVE-2021-41864)

  - The firewire subsystem in the Linux kernel through 5.14.13 has a buffer overflow related to
    drivers/media/firewire/firedtv-avc.c and drivers/media/firewire/firedtv-ci.c, because avc_ca_pmt
    mishandles bounds checking. (CVE-2021-42739)

  - An issue was discovered in the Linux kernel before 5.14.15. There is an array-index-out-of-bounds flaw in
    the detach_capi_ctr function in drivers/isdn/capi/kcapi.c. (CVE-2021-43389)

  - In the Linux kernel through 5.15.2, hw_atl_utils_fw_rpc_wait in
    drivers/net/ethernet/aquantia/atlantic/hw_atl/hw_atl_utils.c allows an attacker (who can introduce a
    crafted device) to trigger an out-of-bounds write via a crafted length value. (CVE-2021-43975)

  - In the Linux kernel through 5.15.2, mwifiex_usb_recv in drivers/net/wireless/marvell/mwifiex/usb.c allows
    an attacker (who can connect a crafted USB device) to cause a denial of service (skb_over_panic).
    (CVE-2021-43976)

  - A use-after-free exists in drivers/tee/tee_shm.c in the TEE subsystem in the Linux kernel through 5.15.11.
    This occurs because of a race condition in tee_shm_get_from_id during an attempt to free a shared memory
    object. (CVE-2021-44733)

  - pep_sock_accept in net/phonet/pep.c in the Linux kernel through 5.15.8 has a refcount leak.
    (CVE-2021-45095)

  - In __f2fs_setxattr in fs/f2fs/xattr.c in the Linux kernel through 5.15.11, there is an out-of-bounds
    memory access when an inode has an invalid last xattr entry. (CVE-2021-45469)

  - An issue was discovered in the Linux kernel before 5.15.11. There is a memory leak in the
    __rds_conn_create() function in net/rds/connection.c in a certain combination of circumstances.
    (CVE-2021-45480)

  - A use-after-free vulnerability was found in rtsx_usb_ms_drv_remove in drivers/memstick/host/rtsx_usb_ms.c
    in memstick in the Linux kernel. In this flaw, a local attacker with a user privilege may impact system
    Confidentiality. This flaw affects kernel versions prior to 5.14 rc1. (CVE-2022-0487)

  - A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the
    kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups
    v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.
    (CVE-2022-0492)

  - A flaw null pointer dereference in the Linux kernel UDF file system functionality was found in the way
    user triggers udf_file_write_iter function for the malicious UDF image. A local user could use this flaw
    to crash the system. Actual from Linux kernel 4.2-rc1 till 5.17-rc2. (CVE-2022-0617)

  - An issue was discovered in fs/nfs/dir.c in the Linux kernel before 5.16.5. If an application sets the
    O_DIRECTORY flag, and tries to open a regular file, nfs_atomic_open() performs a regular lookup. If a
    regular file is found, ENOTDIR should occur, but the server instead returns uninitialized data in the file
    descriptor. (CVE-2022-24448)

  - An issue was discovered in the Linux kernel before 5.16.5. There is a memory leak in yam_siocdevprivate in
    drivers/net/hamradio/yam.c. (CVE-2022-24959)

  - An issue was discovered in drivers/usb/gadget/composite.c in the Linux kernel before 5.16.10. The USB
    Gadget subsystem lacks certain validation of interface OS descriptor requests (ones with a large array
    index and ones associated with NULL function pointer retrieval). Memory corruption might occur.
    (CVE-2022-25258)

  - An issue was discovered in drivers/usb/gadget/function/rndis.c in the Linux kernel before 5.16.10. The
    RNDIS USB gadget lacks validation of the size of the RNDIS_MSG_SET command. Attackers can obtain sensitive
    information from kernel memory. (CVE-2022-25375)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=988044");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5096");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-29374");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-36322");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20317");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20321");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20322");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22600");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28711");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28712");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28713");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28714");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28715");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28950");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3640");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3744");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3752");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3760");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3764");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3772");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38300");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39685");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39686");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39698");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39713");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4002");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4083");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4135");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4155");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41864");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4202");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4203");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-42739");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43389");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43975");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43976");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44733");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45095");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45469");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45480");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0001");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0002");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0322");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0330");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0435");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0487");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0492");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0617");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0644");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-22942");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24448");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24959");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-25258");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-25375");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0435");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'vmwgfx Driver File Descriptor Handling Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbpf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbpf4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblockdep-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblockdep4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-mips64el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-mipsel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-ppc64el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-s390x-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.19.0-19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lockdep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'hyperv-daemons', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'libbpf-dev', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'libbpf4.19', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'libcpupower-dev', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'libcpupower1', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'liblockdep-dev', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'liblockdep4.19', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-arm', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-s390', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-x86', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-config-4.19', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-cpupower', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-doc-4.19', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-4kc-malta', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-5kc-malta', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-686', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-686-pae', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-amd64', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-arm64', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-armel', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-armhf', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-i386', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-mips', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-mips64el', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-mipsel', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-ppc64el', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-s390x', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-amd64', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-arm64', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-armmp', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-armmp-lpae', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-cloud-amd64', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-common', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-common-rt', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-loongson-3', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-marvell', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-octeon', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-powerpc64le', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rpi', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-686-pae', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-amd64', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-arm64', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-armmp', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-s390x', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-4kc-malta', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-4kc-malta-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-5kc-malta', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-5kc-malta-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-pae-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-pae-unsigned', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-unsigned', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-amd64-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-amd64-unsigned', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-arm64-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-arm64-unsigned', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp-lpae', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp-lpae-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-cloud-amd64-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-cloud-amd64-unsigned', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-loongson-3', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-loongson-3-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-marvell', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-marvell-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-octeon', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-octeon-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-powerpc64le', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-powerpc64le-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rpi', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rpi-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-686-pae-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-686-pae-unsigned', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-amd64-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-amd64-unsigned', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-arm64-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-arm64-unsigned', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-armmp', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-armmp-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-s390x', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-s390x-dbg', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-kbuild-4.19', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-libc-dev', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-perf-4.19', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-source-4.19', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'linux-support-4.19.0-19', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'lockdep', 'reference': '4.19.232-1'},
    {'release': '10.0', 'prefix': 'usbip', 'reference': '4.19.232-1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hyperv-daemons / libbpf-dev / libbpf4.19 / libcpupower-dev / etc');
}
