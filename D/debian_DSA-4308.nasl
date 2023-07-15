#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4308. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117862);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/17");

  script_cve_id("CVE-2018-10902", "CVE-2018-10938", "CVE-2018-13099", "CVE-2018-14609", "CVE-2018-14617", "CVE-2018-14633", "CVE-2018-14678", "CVE-2018-14734", "CVE-2018-15572", "CVE-2018-15594", "CVE-2018-16276", "CVE-2018-16658", "CVE-2018-17182", "CVE-2018-6554", "CVE-2018-6555", "CVE-2018-7755", "CVE-2018-9363", "CVE-2018-9516");
  script_xref(name:"DSA", value:"4308");

  script_name(english:"Debian DSA-4308-1 : linux - security update");
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

  - CVE-2018-6554
    A memory leak in the irda_bind function in the irda
    subsystem was discovered. A local user can take
    advantage of this flaw to cause a denial of service
    (memory consumption).

  - CVE-2018-6555
    A flaw was discovered in the irda_setsockopt function in
    the irda subsystem, allowing a local user to cause a
    denial of service (use-after-free and system crash).

  - CVE-2018-7755
    Brian Belleville discovered a flaw in the
    fd_locked_ioctl function in the floppy driver in the
    Linux kernel. The floppy driver copies a kernel pointer
    to user memory in response to the FDGETPRM ioctl. A
    local user with access to a floppy drive device can take
    advantage of this flaw to discover the location kernel
    code and data.

  - CVE-2018-9363
    It was discovered that the Bluetooth HIDP implementation
    did not correctly check the length of received report
    messages. A paired HIDP device could use this to cause a
    buffer overflow, leading to denial of service (memory
    corruption or crash) or potentially remote code
    execution.

  - CVE-2018-9516
    It was discovered that the HID events interface in
    debugfs did not correctly limit the length of copies to
    user buffers. A local user with access to these files
    could use this to cause a denial of service (memory
    corruption or crash) or possibly for privilege
    escalation. However, by default debugfs is only
    accessible by the root user.

  - CVE-2018-10902
    It was discovered that the rawmidi kernel driver does
    not protect against concurrent access which leads to a
    double-realloc (double free) flaw. A local attacker can
    take advantage of this issue for privilege escalation.

  - CVE-2018-10938
    Yves Younan from Cisco reported that the Cipso IPv4
    module did not correctly check the length of IPv4
    options. On custom kernels with CONFIG_NETLABEL enabled,
    a remote attacker could use this to cause a denial of
    service (hang).

  - CVE-2018-13099
    Wen Xu from SSLab at Gatech reported a use-after-free
    bug in the F2FS implementation. An attacker able to
    mount a crafted F2FS volume could use this to cause a
    denial of service (crash or memory corruption) or
    possibly for privilege escalation.

  - CVE-2018-14609
    Wen Xu from SSLab at Gatech reported a potential NULL
    pointer dereference in the F2FS implementation. An
    attacker able to mount a crafted F2FS volume could use
    this to cause a denial of service (crash).

  - CVE-2018-14617
    Wen Xu from SSLab at Gatech reported a potential NULL
    pointer dereference in the HFS+ implementation. An
    attacker able to mount a crafted HFS+ volume could use
    this to cause a denial of service (crash).

  - CVE-2018-14633
    Vincent Pelletier discovered a stack-based buffer
    overflow flaw in the chap_server_compute_md5() function
    in the iSCSI target code. An unauthenticated remote
    attacker can take advantage of this flaw to cause a
    denial of service or possibly to get a non-authorized
    access to data exported by an iSCSI target.

  - CVE-2018-14678
    M. Vefa Bicakci and Andy Lutomirski discovered a flaw in
    the kernel exit code used on amd64 systems running as
    Xen PV guests. A local user could use this to cause a
    denial of service (crash).

  - CVE-2018-14734
    A use-after-free bug was discovered in the InfiniBand
    communication manager. A local user could use this to
    cause a denial of service (crash or memory corruption)
    or possible for privilege escalation.

  - CVE-2018-15572
    Esmaiel Mohammadian Koruyeh, Khaled Khasawneh, Chengyu
    Song, and Nael Abu-Ghazaleh, from University of
    California, Riverside, reported a variant of Spectre
    variant 2, dubbed SpectreRSB. A local user may be able
    to use this to read sensitive information from processes
    owned by other users.

  - CVE-2018-15594
    Nadav Amit reported that some indirect function calls
    used in paravirtualised guests were vulnerable to
    Spectre variant 2. A local user may be able to use this
    to read sensitive information from the kernel.

  - CVE-2018-16276
    Jann Horn discovered that the yurex driver did not
    correctly limit the length of copies to user buffers. A
    local user with access to a yurex device node could use
    this to cause a denial of service (memory corruption or
    crash) or possibly for privilege escalation.

  - CVE-2018-16658
    It was discovered that the cdrom driver does not
    correctly validate the parameter to the
    CDROM_DRIVE_STATUS ioctl. A user with access to a cdrom
    device could use this to read sensitive information from
    the kernel or to cause a denial of service (crash).

  - CVE-2018-17182
    Jann Horn discovered that the vmacache_flush_all
    function mishandles sequence number overflows. A local
    user can take advantage of this flaw to trigger a
    use-after-free, causing a denial of service (crash or
    memory corruption) or privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-7755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-9363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-9516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-10902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-10938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-13099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-14609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-14617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-14633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-14678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-14734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-15572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-15594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-17182"
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
    value:"https://www.debian.org/security/2018/dsa-4308"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the linux packages.

For the stable distribution (stretch), these problems have been fixed
in version 4.9.110-3+deb9u5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14633");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"hyperv-daemons", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower-dev", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower1", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libusbip-dev", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-arm", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-s390", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-x86", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-cpupower", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-doc-4.9", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-4kc-malta", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-5kc-malta", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686-pae", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-amd64", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-arm64", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armel", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armhf", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-i386", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips64el", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mipsel", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-ppc64el", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-s390x", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-amd64", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-arm64", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp-lpae", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common-rt", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-loongson-3", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-marvell", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-octeon", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-powerpc64le", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-686-pae", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-amd64", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-s390x", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta-dbg", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta-dbg", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-dbg", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae-dbg", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64-dbg", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64-dbg", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-dbg", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae-dbg", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3-dbg", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell-dbg", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon-dbg", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le-dbg", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae-dbg", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64-dbg", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x-dbg", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-kbuild-4.9", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-libc-dev", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-manual-4.9", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-perf-4.9", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-source-4.9", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-support-4.9.0-9", reference:"4.9.110-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"usbip", reference:"4.9.110-3+deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
