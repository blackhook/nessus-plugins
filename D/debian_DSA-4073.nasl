#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4073. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105433);
  script_version("3.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-1000407", "CVE-2017-1000410", "CVE-2017-16538", "CVE-2017-16644", "CVE-2017-16995", "CVE-2017-17448", "CVE-2017-17449", "CVE-2017-17450", "CVE-2017-17558", "CVE-2017-17712", "CVE-2017-17741", "CVE-2017-17805", "CVE-2017-17806", "CVE-2017-17807", "CVE-2017-17862", "CVE-2017-17863", "CVE-2017-17864", "CVE-2017-8824");
  script_xref(name:"DSA", value:"4073");

  script_name(english:"Debian DSA-4073-1 : linux - security update");
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

  - CVE-2017-8824
    Mohamed Ghannam discovered that the DCCP implementation
    did not correctly manage resources when a socket is
    disconnected and reconnected, potentially leading to a
    use-after-free. A local user could use this for denial
    of service (crash or data corruption) or possibly for
    privilege escalation. On systems that do not already
    have the dccp module loaded, this can be mitigated by
    disabling it:echo >> /etc/modprobe.d/disable-dccp.conf
    install dccp false

  - CVE-2017-16538
    Andrey Konovalov reported that the dvb-usb-lmedm04 media
    driver did not correctly handle some error conditions
    during initialisation. A physically present user with a
    specially designed USB device can use this to cause a
    denial of service (crash).

  - CVE-2017-16644
    Andrey Konovalov reported that the hdpvr media driver
    did not correctly handle some error conditions during
    initialisation. A physically present user with a
    specially designed USB device can use this to cause a
    denial of service (crash).

  - CVE-2017-16995
    Jann Horn discovered that the Extended BPF verifier did
    not correctly model the behaviour of 32-bit load
    instructions. A local user can use this for privilege
    escalation.

  - CVE-2017-17448
    Kevin Cernekee discovered that the netfilter subsystem
    allowed users with the CAP_NET_ADMIN capability in any
    user namespace, not just the root namespace, to enable
    and disable connection tracking helpers. This could lead
    to denial of service, violation of network security
    policy, or have other impact.

  - CVE-2017-17449
    Kevin Cernekee discovered that the netlink subsystem
    allowed users with the CAP_NET_ADMIN capability in any
    user namespace to monitor netlink traffic in all net
    namespaces, not just those owned by that user namespace.
    This could lead to exposure of sensitive information.

  - CVE-2017-17450
    Kevin Cernekee discovered that the xt_osf module allowed
    users with the CAP_NET_ADMIN capability in any user
    namespace to modify the global OS fingerprint list.

  - CVE-2017-17558
    Andrey Konovalov reported that that USB core did not
    correctly handle some error conditions during
    initialisation. A physically present user with a
    specially designed USB device can use this to cause a
    denial of service (crash or memory corruption), or
    possibly for privilege escalation.

  - CVE-2017-17712
    Mohamed Ghannam discovered a race condition in the IPv4
    raw socket implementation. A local user could use this
    to obtain sensitive information from the kernel.

  - CVE-2017-17741
    Dmitry Vyukov reported that the KVM implementation for
    x86 would over-read data from memory when emulating an
    MMIO write if the kvm_mmio tracepoint was enabled. A
    guest virtual machine might be able to use this to cause
    a denial of service (crash).

  - CVE-2017-17805
    It was discovered that some implementations of the
    Salsa20 block cipher did not correctly handle
    zero-length input. A local user could use this to cause
    a denial of service (crash) or possibly have other
    security impact.

  - CVE-2017-17806
    It was discovered that the HMAC implementation could be
    used with an underlying hash algorithm that requires a
    key, which was not intended. A local user could use this
    to cause a denial of service (crash or memory
    corruption), or possibly for privilege escalation.

  - CVE-2017-17807
    Eric Biggers discovered that the KEYS subsystem lacked a
    check for write permission when adding keys to a
    process's default keyring. A local user could use this
    to cause a denial of service or to obtain sensitive
    information.

  - CVE-2017-17862
    Alexei Starovoitov discovered that the Extended BPF
    verifier ignored unreachable code, even though it would
    still be processed by JIT compilers. This could possibly
    be used by local users for denial of service. It also
    increases the severity of bugs in determining
    unreachable code.

  - CVE-2017-17863
    Jann Horn discovered that the Extended BPF verifier did
    not correctly model pointer arithmetic on the stack
    frame pointer. A local user can use this for privilege
    escalation.

  - CVE-2017-17864
    Jann Horn discovered that the Extended BPF verifier
    could fail to detect pointer leaks from conditional
    code. A local user could use this to obtain sensitive
    information in order to exploit other vulnerabilities.

  - CVE-2017-1000407
    Andrew Honig reported that the KVM implementation for
    Intel processors allowed direct access to host I/O port
    0x80, which is not generally safe. On some systems this
    allows a guest VM to cause a denial of service (crash)
    of the host.

  - CVE-2017-1000410
    Ben Seri reported that the Bluetooth subsystem did not
    correctly handle short EFS information elements in L2CAP
    messages. An attacker able to communicate over Bluetooth
    could use this to obtain sensitive information from the
    kernel.

The various problems in the Extended BPF verifier can be mitigated by
disabling use of Extended BPF by unprivileged users:sysctl
kernel.unprivileged_bpf_disabled=1

Debian disables unprivileged user namespaces by default, but if they
are enabled (via the kernel.unprivileged_userns_clone sysctl) then
CVE-2017-17448 can be exploited by any local user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-8824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-16538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-16644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-16995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17448"
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
    value:"https://www.debian.org/security/2017/dsa-4073"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the stable distribution (stretch), these problems have been fixed
in version 4.9.65-3+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BPF Sign Extension Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"hyperv-daemons", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower-dev", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower1", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libusbip-dev", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-arm", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-s390", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-x86", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-cpupower", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-doc-4.9", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-4kc-malta", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-5kc-malta", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686-pae", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-amd64", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-arm64", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armel", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armhf", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-i386", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips64el", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mipsel", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-ppc64el", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-s390x", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-amd64", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-arm64", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp-lpae", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common-rt", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-loongson-3", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-marvell", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-octeon", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-powerpc64le", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-686-pae", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-amd64", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-s390x", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta-dbg", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta-dbg", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-dbg", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae-dbg", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64-dbg", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64-dbg", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-dbg", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae-dbg", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3-dbg", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell-dbg", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon-dbg", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le-dbg", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae-dbg", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64-dbg", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x-dbg", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-kbuild-4.9", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-libc-dev", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-manual-4.9", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-perf-4.9", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-source-4.9", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-support-4.9.0-9", reference:"4.9.65-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"usbip", reference:"4.9.65-3+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
