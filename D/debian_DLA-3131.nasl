#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3131. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(165623);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id(
    "CVE-2021-4159",
    "CVE-2021-33655",
    "CVE-2021-33656",
    "CVE-2022-1462",
    "CVE-2022-1679",
    "CVE-2022-2153",
    "CVE-2022-2318",
    "CVE-2022-2586",
    "CVE-2022-2588",
    "CVE-2022-2663",
    "CVE-2022-3028",
    "CVE-2022-26365",
    "CVE-2022-26373",
    "CVE-2022-33740",
    "CVE-2022-33741",
    "CVE-2022-33742",
    "CVE-2022-33744",
    "CVE-2022-36879",
    "CVE-2022-36946",
    "CVE-2022-39188",
    "CVE-2022-39842",
    "CVE-2022-40307"
  );

  script_name(english:"Debian DLA-3131-1 : linux - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3131 advisory.

  - When sending malicous data to kernel by ioctl cmd FBIOPUT_VSCREENINFO,kernel will write memory out of
    bounds. (CVE-2021-33655)

  - When setting font with malicous data by ioctl cmd PIO_FONT,kernel will write memory out of bounds.
    (CVE-2021-33656)

  - A vulnerability was found in the Linux kernel's EBPF verifier when handling internal data structures.
    Internal memory locations could be returned to userspace. A local attacker with the permissions to insert
    eBPF code to the kernel can use this to leak internal kernel memory details defeating some of the exploit
    mitigations in place for the kernel. (CVE-2021-4159)

  - An out-of-bounds read flaw was found in the Linux kernel's TeleTYpe subsystem. The issue occurs in how a
    user triggers a race condition using ioctls TIOCSPTLCK and TIOCGPTPEER and TIOCSTI and TCXONC with leakage
    of memory in the flush_to_ldisc function. This flaw allows a local user to crash the system or read
    unauthorized random data from memory. (CVE-2022-1462)

  - A use-after-free flaw was found in the Linux kernel's Atheros wireless adapter driver in the way a user
    forces the ath9k_htc_wait_for_target function to fail with some input messages. This flaw allows a local
    user to crash or potentially escalate their privileges on the system. (CVE-2022-1679)

  - A flaw was found in the Linux kernel's KVM when attempting to set a SynIC IRQ. This issue makes it
    possible for a misbehaving VMM to write to SYNIC/STIMER MSRs, causing a NULL pointer dereference. This
    flaw allows an unprivileged local attacker on the host to issue specific ioctl calls, causing a kernel
    oops condition that results in a denial of service. (CVE-2022-2153)

  - There are use-after-free vulnerabilities caused by timer handler in net/rose/rose_timer.c of linux that
    allow attackers to crash linux kernel without any privileges. (CVE-2022-2318)

  - An out-of-bounds read flaw was found in the Linux kernel's TeleTYpe subsystem. The issue occurs in how a
    user triggers a race condition using ioctls TIOCSPTLCK and TIOCGPTPEER and TIOCSTI and TCXONC with leakage
    of memory in the flush_to_ldisc function. This flaw allows a local user to crash the system or read
    unauthorized random data from memory. (CVE-2022-1462) (CVE-2022-2586)

  - kernel: a use-after-free in cls_route filter implementation may lead to privilege escalation
    (CVE-2022-2588)

  - Linux disk/nic frontends data leaks T[his CNA information record relates to multiple CVEs; the text
    explains which aspects/vulnerabilities correspond to which CVE.] Linux Block and Network PV device
    frontends don't zero memory regions before sharing them with the backend (CVE-2022-26365, CVE-2022-33740).
    Additionally the granularity of the grant table doesn't allow sharing less than a 4K page, leading to
    unrelated data residing in the same 4K page as data shared with a backend being accessible by such backend
    (CVE-2022-33741, CVE-2022-33742). (CVE-2022-26365, CVE-2022-33740, CVE-2022-33741, CVE-2022-33742)

  - Non-transparent sharing of return predictor targets between contexts in some Intel(R) Processors may allow
    an authorized user to potentially enable information disclosure via local access. (CVE-2022-26373)

  - An issue was found in the Linux kernel in nf_conntrack_irc where the message handling can be confused and
    incorrectly matches the message. A firewall may be able to be bypassed when users are using unencrypted
    IRC with nf_conntrack_irc configured. (CVE-2022-2663)

  - A race condition was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem)
    when multiple calls to xfrm_probe_algs occurred simultaneously. This flaw could allow a local attacker to
    potentially trigger an out-of-bounds write or leak kernel heap memory by performing an out-of-bounds read
    and copying it into a socket. (CVE-2022-3028)

  - Arm guests can cause Dom0 DoS via PV devices When mapping pages of guests on Arm, dom0 is using an rbtree
    to keep track of the foreign mappings. Updating of that rbtree is not always done completely with the
    related lock held, resulting in a small race window, which can be used by unprivileged guests via PV
    devices to cause inconsistencies of the rbtree. These inconsistencies can lead to Denial of Service (DoS)
    of dom0, e.g. by causing crashes or the inability to perform further mappings of other guests' memory
    pages. (CVE-2022-33744)

  - An issue was discovered in the Linux kernel through 5.18.14. xfrm_expand_policies in
    net/xfrm/xfrm_policy.c can cause a refcount to be dropped twice. (CVE-2022-36879)

  - nfqnl_mangle in net/netfilter/nfnetlink_queue.c in the Linux kernel through 5.18.14 allows remote
    attackers to cause a denial of service (panic) because, in the case of an nf_queue verdict with a one-byte
    nfta_payload attribute, an skb_pull can encounter a negative skb->len. (CVE-2022-36946)

  - An issue was discovered in include/asm-generic/tlb.h in the Linux kernel before 5.19. Because of a race
    condition (unmap_mapping_range versus munmap), a device driver can free a page while it still has stale
    TLB entries. This only occurs in situations with VM_PFNMAP VMAs. (CVE-2022-39188)

  - An issue was discovered in the Linux kernel before 5.19. In pxa3xx_gcu_write in
    drivers/video/fbdev/pxa3xx-gcu.c, the count parameter has a type conflict of size_t versus int, causing an
    integer overflow and bypassing the size check. After that, because it is used as the third argument to
    copy_from_user(), a heap overflow may occur. (CVE-2022-39842)

  - An issue was discovered in the Linux kernel through 5.19.8. drivers/firmware/efi/capsule-loader.c has a
    race condition with a resultant use-after-free. (CVE-2022-40307)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1018752");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3131");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33655");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33656");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4159");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1462");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1679");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2153");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2318");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2586");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2588");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26365");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26373");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2663");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3028");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33740");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33741");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33742");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33744");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36879");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36946");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39188");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39842");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-40307");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux packages.

For Debian 10 buster, these problems have been fixed in version 4.19.260-1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1679");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbpf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbpf4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-armmp");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.19.0-19");
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
    {'release': '10.0', 'prefix': 'hyperv-daemons', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'libbpf-dev', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'libbpf4.19', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'libcpupower-dev', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'libcpupower1', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-arm', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-x86', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-config-4.19', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-cpupower', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-doc-4.19', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-686', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-686-pae', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-amd64', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-arm64', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-armhf', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-i386', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-amd64', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-arm64', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-armmp', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-armmp-lpae', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-cloud-amd64', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-common', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-common-rt', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-686-pae', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-amd64', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-arm64', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-armmp', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-pae-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-pae-unsigned', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-unsigned', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-amd64-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-amd64-unsigned', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-arm64-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-arm64-unsigned', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp-lpae', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp-lpae-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-cloud-amd64-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-cloud-amd64-unsigned', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-686-pae-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-686-pae-unsigned', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-amd64-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-amd64-unsigned', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-arm64-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-arm64-unsigned', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-armmp', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-armmp-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-kbuild-4.19', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-libc-dev', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-perf-4.19', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-source-4.19', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-support-4.19.0-19', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'usbip', 'reference': '4.19.260-1'}
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
