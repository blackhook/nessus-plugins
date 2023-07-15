#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4187. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109517);
  script_version("1.9");
  script_cvs_date("Date: 2020/01/23");

  script_cve_id("CVE-2015-9016", "CVE-2017-0861", "CVE-2017-13166", "CVE-2017-13220", "CVE-2017-16526", "CVE-2017-16911", "CVE-2017-16912", "CVE-2017-16913", "CVE-2017-16914", "CVE-2017-18017", "CVE-2017-18203", "CVE-2017-18216", "CVE-2017-18232", "CVE-2017-18241", "CVE-2017-5715", "CVE-2017-5753", "CVE-2018-1000004", "CVE-2018-1000199", "CVE-2018-1066", "CVE-2018-1068", "CVE-2018-1092", "CVE-2018-5332", "CVE-2018-5333", "CVE-2018-5750", "CVE-2018-5803", "CVE-2018-6927", "CVE-2018-7492", "CVE-2018-7566", "CVE-2018-7740", "CVE-2018-7757", "CVE-2018-7995", "CVE-2018-8781", "CVE-2018-8822");
  script_xref(name:"DSA", value:"4187");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"Debian DSA-4187-1 : linux - security update (Spectre)");
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

  - CVE-2015-9016
    Ming Lei reported a race condition in the multiqueue
    block layer (blk-mq). On a system with a driver using
    blk-mq (mtip32xx, null_blk, or virtio_blk), a local user
    might be able to use this for denial of service or
    possibly for privilege escalation.

  - CVE-2017-0861
    Robb Glasser reported a potential use-after-free in the
    ALSA (sound) PCM core. We believe this was not possible
    in practice.

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

  - CVE-2017-13166
    A bug in the 32-bit compatibility layer of the v4l2
    ioctl handling code has been found. Memory protections
    ensuring user-provided buffers always point to userland
    memory were disabled, allowing destination addresses to
    be in kernel space. On a 64-bit kernel a local user with
    access to a suitable video device can exploit this to
    overwrite kernel memory, leading to privilege
    escalation.

  - CVE-2017-13220
    Al Viro reported that the Bluetooth HIDP implementation
    could dereference a pointer before performing the
    necessary type check. A local user could use this to
    cause a denial of service.

  - CVE-2017-16526
    Andrey Konovalov reported that the UWB subsystem may
    dereference an invalid pointer in an error case. A local
    user might be able to use this for denial of service.

  - CVE-2017-16911
    Secunia Research reported that the USB/IP vhci_hcd
    driver exposed kernel heap addresses to local users.
    This information could aid the exploitation of other
    vulnerabilities.

  - CVE-2017-16912
    Secunia Research reported that the USB/IP stub driver
    failed to perform a range check on a received packet
    header field, leading to an out-of-bounds read. A remote
    user able to connect to the USB/IP server could use this
    for denial of service.

  - CVE-2017-16913
    Secunia Research reported that the USB/IP stub driver
    failed to perform a range check on a received packet
    header field, leading to excessive memory allocation. A
    remote user able to connect to the USB/IP server could
    use this for denial of service.

  - CVE-2017-16914
    Secunia Research reported that the USB/IP stub driver
    failed to check for an invalid combination of fields in
    a received packet, leading to a NULL pointer
    dereference. A remote user able to connect to the USB/IP
    server could use this for denial of service.

  - CVE-2017-18017
    Denys Fedoryshchenko reported that the netfilter
    xt_TCPMSS module failed to validate TCP header lengths,
    potentially leading to a use-after-free. If this module
    is loaded, it could be used by a remote attacker for
    denial of service or possibly for code execution.

  - CVE-2017-18203
    Hou Tao reported that there was a race condition in
    creation and deletion of device-mapper (DM) devices. A
    local user could potentially use this for denial of
    service.

  - CVE-2017-18216
    Alex Chen reported that the OCFS2 filesystem failed to
    hold a necessary lock during nodemanager sysfs file
    operations, potentially leading to a NULL pointer
    dereference. A local user could use this for denial of
    service.

  - CVE-2017-18232
    Jason Yan reported a race condition in the SAS
    (Serial-Attached SCSI) subsystem, between probing and
    destroying a port. This could lead to a deadlock. A
    physically present attacker could use this to cause a
    denial of service.

  - CVE-2017-18241
    Yunlei He reported that the f2fs implementation does not
    properly initialise its state if the 'noflush_merge'
    mount option is used. A local user with access to a
    filesystem mounted with this option could use this to
    cause a denial of service.

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

  - CVE-2018-5332
    Mohamed Ghannam reported that the RDS protocol did not
    sufficiently validate RDMA requests, leading to an
    out-of-bounds write. A local attacker on a system with
    the rds module loaded could use this for denial of
    service or possibly for privilege escalation.

  - CVE-2018-5333
    Mohamed Ghannam reported that the RDS protocol did not
    properly handle an error case, leading to a NULL pointer
    dereference. A local attacker on a system with the rds
    module loaded could possibly use this for denial of
    service.

  - CVE-2018-5750
    Wang Qize reported that the ACPI sbshc driver logged a
    kernel heap address. This information could aid the
    exploitation of other vulnerabilities.

  - CVE-2018-5803
    Alexey Kodanev reported that the SCTP protocol did not
    range-check the length of chunks to be created. A local
    or remote user could use this to cause a denial of
    service.

  - CVE-2018-6927
    Li Jinyue reported that the FUTEX_REQUEUE operation on
    futexes did not check for negative parameter values,
    which might lead to a denial of service or other
    security impact.

  - CVE-2018-7492
    The syzkaller tool found that the RDS protocol was
    lacking a null pointer check. A local attacker on a
    system with the rds module loaded could use this for
    denial of service.

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

  - CVE-2018-1000004
    Luo Quan reported a race condition in the ALSA (sound)
    sequencer core, between multiple ioctl operations. This
    could lead to a deadlock or use-after-free. A local user
    with access to a sequencer device could use this for
    denial of service or possibly for privilege escalation.

  - CVE-2018-1000199
    Andy Lutomirski discovered that the ptrace subsystem did
    not sufficiently validate hardware breakpoint settings.
    Local users can use this to cause a denial of service,
    or possibly for privilege escalation, on x86 (amd64 and
    i386) and possibly other architectures."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-9016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-0861"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2017-13166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-13220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-16526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-16911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-16912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-16913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-16914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-18017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-18203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-18216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-18232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-18241"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2018-5332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-5333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-5750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-5803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-7492"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2018-8781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-8822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1000004"
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
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4187"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 3.16.56-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Reliable Datagram Sockets (RDS) rds_atomic_free_op NULL pointer dereference Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-x86", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-586", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-686-pae", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-amd64", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armel", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armhf", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-i386", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-amd64", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp-lpae", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-common", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-ixp4xx", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-kirkwood", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-orion5x", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-versatile", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-586", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae-dbg", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64-dbg", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp-lpae", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-ixp4xx", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-kirkwood", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-orion5x", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-versatile", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-9", reference:"3.16.56-1")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-9-amd64", reference:"3.16.56-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
