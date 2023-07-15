#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4188. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109518);
  script_version("1.10");
  script_cvs_date("Date: 2019/07/15 14:20:30");

  script_cve_id("CVE-2017-17975", "CVE-2017-18193", "CVE-2017-18216", "CVE-2017-18218", "CVE-2017-18222", "CVE-2017-18224", "CVE-2017-18241", "CVE-2017-18257", "CVE-2017-5715", "CVE-2017-5753", "CVE-2018-1000199", "CVE-2018-10323", "CVE-2018-1065", "CVE-2018-1066", "CVE-2018-1068", "CVE-2018-1092", "CVE-2018-1093", "CVE-2018-1108", "CVE-2018-5803", "CVE-2018-7480", "CVE-2018-7566", "CVE-2018-7740", "CVE-2018-7757", "CVE-2018-7995", "CVE-2018-8087", "CVE-2018-8781", "CVE-2018-8822");
  script_xref(name:"DSA", value:"4188");

  script_name(english:"Debian DSA-4188-1 : linux - security update (Spectre)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

  - CVE-2017-5715
    Multiple researchers have discovered a vulnerability in
    various processors supporting speculative execution,
    enabling an attacker controlling an unprivileged process
    to read memory from arbitrary addresses, including from
    the kernel and all other processes running on the
    system.

  This specific attack has been named Spectre variant 2 (branch target
  injection) and is mitigated for the x86 architecture (amd64 and
  i386) by using the 'retpoline' compiler feature which allows
  indirect branches to be isolated from speculative execution.

  - CVE-2017-5753
    Multiple researchers have discovered a vulnerability in
    various processors supporting speculative execution,
    enabling an attacker controlling an unprivileged process
    to read memory from arbitrary addresses, including from
    the kernel and all other processes running on the
    system.

  This specific attack has been named Spectre variant 1 (bounds-check
  bypass) and is mitigated by identifying vulnerable code sections
  (array bounds checking followed by array access) and replacing the
  array access with the speculation-safe array_index_nospec()
  function.

  More use sites will be added over time.

  - CVE-2017-17975
    Tuba Yavuz reported a use-after-free flaw in the
    USBTV007 audio-video grabber driver. A local user could
    use this for denial of service by triggering failure of
    audio registration.

  - CVE-2017-18193
    Yunlei He reported that the f2fs implementation does not
    properly handle extent trees, allowing a local user to
    cause a denial of service via an application with
    multiple threads.

  - CVE-2017-18216
    Alex Chen reported that the OCFS2 filesystem failed to
    hold a necessary lock during nodemanager sysfs file
    operations, potentially leading to a NULL pointer
    dereference. A local user could use this for denial of
    service.

  - CVE-2017-18218
    Jun He reported a use-after-free flaw in the Hisilicon
    HNS ethernet driver. A local user could use this for
    denial of service.

  - CVE-2017-18222
    It was reported that the Hisilicon Network Subsystem
    (HNS) driver implementation does not properly handle
    ethtool private flags. A local user could use this for
    denial of service or possibly have other impact.

  - CVE-2017-18224
    Alex Chen reported that the OCFS2 filesystem omits the
    use of a semaphore and consequently has a race condition
    for access to the extent tree during read operations in
    DIRECT mode. A local user could use this for denial of
    service.

  - CVE-2017-18241
    Yunlei He reported that the f2fs implementation does not
    properly initialise its state if the 'noflush_merge'
    mount option is used. A local user with access to a
    filesystem mounted with this option could use this to
    cause a denial of service.

  - CVE-2017-18257
    It was reported that the f2fs implementation is prone to
    an infinite loop caused by an integer overflow in the
    __get_data_block() function. A local user can use this
    for denial of service via crafted use of the open and
    fallocate system calls with an FS_IOC_FIEMAP ioctl.

  - CVE-2018-1065
    The syzkaller tool found a NULL pointer dereference flaw
    in the netfilter subsystem when handling certain
    malformed iptables rulesets. A local user with the
    CAP_NET_RAW or CAP_NET_ADMIN capability (in any user
    namespace) could use this to cause a denial of service.
    Debian disables unprivileged user namespaces by default.

  - CVE-2018-1066
    Dan Aloni reported to Red Hat that the CIFS client
    implementation would dereference a NULL pointer if the
    server sent an invalid response during NTLMSSP setup
    negotiation. This could be used by a malicious server
    for denial of service.

  - CVE-2018-1068
    The syzkaller tool found that the 32-bit compatibility
    layer of ebtables did not sufficiently validate offset
    values. On a 64-bit kernel, a local user with the
    CAP_NET_ADMIN capability (in any user namespace) could
    use this to overwrite kernel memory, possibly leading to
    privilege escalation. Debian disables unprivileged user
    namespaces by default.

  - CVE-2018-1092
    Wen Xu reported that a crafted ext4 filesystem image
    would trigger a null dereference when mounted. A local
    user able to mount arbitrary filesystems could use this
    for denial of service.

  - CVE-2018-1093
    Wen Xu reported that a crafted ext4 filesystem image
    could trigger an out-of-bounds read in the
    ext4_valid_block_bitmap() function. A local user able to
    mount arbitrary filesystems could use this for denial of
    service.

  - CVE-2018-1108
    Jann Horn reported that crng_ready() does not properly
    handle the crng_init variable states and the RNG could
    be treated as cryptographically safe too early after
    system boot.

  - CVE-2018-5803
    Alexey Kodanev reported that the SCTP protocol did not
    range-check the length of chunks to be created. A local
    or remote user could use this to cause a denial of
    service.

  - CVE-2018-7480
    Hou Tao discovered a double-free flaw in the
    blkcg_init_queue() function in block/blk-cgroup.c. A
    local user could use this to cause a denial of service
    or have other impact.

  - CVE-2018-7566
    Fan LongFei reported a race condition in the ALSA
    (sound) sequencer core, between write and ioctl
    operations. This could lead to an out-of-bounds access
    or use-after-free. A local user with access to a
    sequencer device could use this for denial of service or
    possibly for privilege escalation.

  - CVE-2018-7740
    Nic Losby reported that the hugetlbfs filesystem's mmap
    operation did not properly range-check the file offset.
    A local user with access to files on a hugetlbfs
    filesystem could use this to cause a denial of service.

  - CVE-2018-7757
    Jason Yan reported a memory leak in the SAS
    (Serial-Attached SCSI) subsystem. A local user on a
    system with SAS devices could use this to cause a denial
    of service.

  - CVE-2018-7995
    Seunghun Han reported a race condition in the x86 MCE
    (Machine Check Exception) driver. This is unlikely to
    have any security impact.

  - CVE-2018-8087
    A memory leak flaw was found in the hwsim_new_radio_nl()
    function in the simulated radio testing tool driver for
    mac80211, allowing a local user to cause a denial of
    service.

  - CVE-2018-8781
    Eyal Itkin reported that the udl (DisplayLink) driver's
    mmap operation did not properly range-check the file
    offset. A local user with access to a udl framebuffer
    device could exploit this to overwrite kernel memory,
    leading to privilege escalation.

  - CVE-2018-8822
    Dr Silvio Cesare of InfoSect reported that the ncpfs
    client implementation did not validate reply lengths
    from the server. An ncpfs server could use this to cause
    a denial of service or remote code execution in the
    client.

  - CVE-2018-10323
    Wen Xu reported a NULL pointer dereference flaw in the
    xfs_bmapi_write() function triggered when mounting and
    operating a crafted xfs filesystem image. A local user
    able to mount arbitrary filesystems could use this for
    denial of service.

  - CVE-2018-1000199
    Andy Lutomirski discovered that the ptrace subsystem did
    not sufficiently validate hardware breakpoint settings.
    Local users can use this to cause a denial of service,
    or possibly for privilege escalation, on x86 (amd64 and
    i386) and possibly other architectures."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-18193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-18216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-18218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-18222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-18224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-18241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-18257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-5803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-7480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-7566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-7740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-7757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-7995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-8087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-8781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-8822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-10323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1000199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4188"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the stable distribution (stretch), these problems have been fixed
in version 4.9.88-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"9.0", prefix:"hyperv-daemons", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower-dev", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower1", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"libusbip-dev", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-arm", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-s390", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-x86", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-cpupower", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-doc-4.9", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-4kc-malta", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-5kc-malta", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686-pae", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-amd64", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-arm64", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armel", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armhf", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-i386", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips64el", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mipsel", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-ppc64el", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-s390x", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-amd64", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-arm64", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp-lpae", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common-rt", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-loongson-3", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-marvell", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-octeon", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-powerpc64le", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-686-pae", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-amd64", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-s390x", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta-dbg", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta-dbg", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-dbg", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae-dbg", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64-dbg", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64-dbg", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-dbg", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae-dbg", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3-dbg", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell-dbg", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon-dbg", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le-dbg", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae-dbg", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64-dbg", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x-dbg", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-kbuild-4.9", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-libc-dev", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-manual-4.9", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-perf-4.9", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-source-4.9", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-support-4.9.0-9", reference:"4.9.88-1")) flag++;
if (deb_check(release:"9.0", prefix:"usbip", reference:"4.9.88-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
