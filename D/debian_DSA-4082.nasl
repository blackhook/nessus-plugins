#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4082. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105704);
  script_version("3.10");
  script_cvs_date("Date: 2019/07/15 14:20:30");

  script_cve_id("CVE-2017-1000407", "CVE-2017-1000410", "CVE-2017-15868", "CVE-2017-16538", "CVE-2017-16939", "CVE-2017-17448", "CVE-2017-17449", "CVE-2017-17450", "CVE-2017-17558", "CVE-2017-17741", "CVE-2017-17805", "CVE-2017-17806", "CVE-2017-17807", "CVE-2017-5754", "CVE-2017-8824");
  script_xref(name:"DSA", value:"4082");
  script_xref(name:"IAVA", value:"2018-A-0019");

  script_name(english:"Debian DSA-4082-1 : linux - security update (Meltdown)");
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

  - CVE-2017-5754
    Multiple researchers have discovered a vulnerability in
    Intel processors, enabling an attacker controlling an
    unprivileged process to read memory from arbitrary
    addresses, including from the kernel and all other
    processes running on the system.

  This specific attack has been named Meltdown and is addressed in the
  Linux kernel for the Intel x86-64 architecture by a patch set named
  Kernel Page Table Isolation, enforcing a near complete separation of
  the kernel and userspace address maps and preventing the attack.
  This solution might have a performance impact, and can be disabled
  at boot time by passing pti=off to the kernel command line.

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

  - CVE-2017-15868
    Al Viro found that the Bluebooth Network Encapsulation
    Protocol (BNEP) implementation did not validate the type
    of the second socket passed to the BNEPCONNADD ioctl(),
    which could lead to memory corruption. A local user with
    the CAP_NET_ADMIN capability can use this for denial of
    service (crash or data corruption) or possibly for
    privilege escalation.

  - CVE-2017-16538
    Andrey Konovalov reported that the dvb-usb-lmedm04 media
    driver did not correctly handle some error conditions
    during initialisation. A physically present user with a
    specially designed USB device can use this to cause a
    denial of service (crash).

  - CVE-2017-16939
    Mohamed Ghannam reported (through Beyond Security's
    SecuriTeam Secure Disclosure program) that the IPsec
    (xfrm) implementation did not correctly handle some
    failure cases when dumping policy information through
    netlink. A local user with the CAP_NET_ADMIN capability
    can use this for denial of service (crash or data
    corruption) or possibly for privilege escalation.

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
    kernel."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-8824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-16538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-16939"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000410"
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
    value:"https://www.debian.org/security/2018/dsa-4082"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 3.16.51-3+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/10");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-x86", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-586", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-686-pae", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-amd64", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armel", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armhf", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-i386", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-amd64", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp-lpae", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-common", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-ixp4xx", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-kirkwood", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-orion5x", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-versatile", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-586", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae-dbg", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64-dbg", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp-lpae", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-ixp4xx", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-kirkwood", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-orion5x", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-versatile", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-9", reference:"3.16.51-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-9-amd64", reference:"3.16.51-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
