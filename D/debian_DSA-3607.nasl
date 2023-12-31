#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3607. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91886);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-7515", "CVE-2016-0821", "CVE-2016-1237", "CVE-2016-1583", "CVE-2016-2117", "CVE-2016-2143", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2187", "CVE-2016-3070", "CVE-2016-3134", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-3157", "CVE-2016-3672", "CVE-2016-3951", "CVE-2016-3955", "CVE-2016-3961", "CVE-2016-4470", "CVE-2016-4482", "CVE-2016-4485", "CVE-2016-4486", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4580", "CVE-2016-4581", "CVE-2016-4805", "CVE-2016-4913", "CVE-2016-4997", "CVE-2016-4998", "CVE-2016-5243", "CVE-2016-5244");
  script_xref(name:"DSA", value:"3607");

  script_name(english:"Debian DSA-3607-1 : linux - security update");
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

  - CVE-2015-7515, CVE-2016-2184, CVE-2016-2185,
    CVE-2016-2186, CVE-2016-2187, CVE-2016-3136,
    CVE-2016-3137, CVE-2016-3138, CVE-2016-3140
    Ralf Spenneberg of OpenSource Security reported that
    various USB drivers do not sufficiently validate USB
    descriptors. This allowed a physically present user with
    a specially designed USB device to cause a denial of
    service (crash).

  - CVE-2016-0821
    Solar Designer noted that the list 'poisoning' feature,
    intended to mitigate the effects of bugs in list
    manipulation in the kernel, used poison values within
    the range of virtual addresses that can be allocated by
    user processes.

  - CVE-2016-1237
    David Sinquin discovered that nfsd does not check
    permissions when setting ACLs, allowing users to grant
    themselves permissions to a file by setting the ACL.

  - CVE-2016-1583
    Jann Horn of Google Project Zero reported that the
    eCryptfs filesystem could be used together with the proc
    filesystem to cause a kernel stack overflow. If the
    ecryptfs-utils package is installed, local users could
    exploit this, via the mount.ecryptfs_private program,
    for denial of service (crash) or possibly for privilege
    escalation.

  - CVE-2016-2117
    Justin Yackoski of Cryptonite discovered that the
    Atheros L2 ethernet driver incorrectly enables
    scatter/gather I/O. A remote attacker could take
    advantage of this flaw to obtain potentially sensitive
    information from kernel memory.

  - CVE-2016-2143
    Marcin Koscielnicki discovered that the fork
    implementation in the Linux kernel on s390 platforms
    mishandles the case of four page-table levels, which
    allows local users to cause a denial of service (system
    crash).

  - CVE-2016-3070
    Jan Stancek of Red Hat discovered a local denial of
    service vulnerability in AIO handling.

  - CVE-2016-3134
    The Google Project Zero team found that the netfilter
    subsystem does not sufficiently validate filter table
    entries. A user with the CAP_NET_ADMIN capability could
    use this for denial of service (crash) or possibly for
    privilege escalation. Debian disables unprivileged user
    namespaces by default, if locally enabled with the
    kernel.unprivileged_userns_clone sysctl, this allows
    privilege escalation.

  - CVE-2016-3156
    Solar Designer discovered that the IPv4 implementation
    in the Linux kernel did not perform the destruction of
    inet device objects properly. An attacker in a guest OS
    could use this to cause a denial of service (networking
    outage) in the host OS.

  - CVE-2016-3157 / XSA-171
    Andy Lutomirski discovered that the x86_64 (amd64) task
    switching implementation did not correctly update the
    I/O permission level when running as a Xen paravirtual
    (PV) guest. In some configurations this would allow
    local users to cause a denial of service (crash) or to
    escalate their privileges within the guest.

  - CVE-2016-3672
    Hector Marco and Ismael Ripoll noted that it was
    possible to disable Address Space Layout Randomisation
    (ASLR) for x86_32 (i386) programs by removing the stack
    resource limit. This made it easier for local users to
    exploit security flaws in programs that have the setuid
    or setgid flag set.

  - CVE-2016-3951
    It was discovered that the cdc_ncm driver would free
    memory prematurely if certain errors occurred during its
    initialisation. This allowed a physically present user
    with a specially designed USB device to cause a denial
    of service (crash) or possibly to escalate their
    privileges.

  - CVE-2016-3955
    Ignat Korchagin reported that the usbip subsystem did
    not check the length of data received for a USB buffer.
    This allowed denial of service (crash) or privilege
    escalation on a system configured as a usbip client, by
    the usbip server or by an attacker able to impersonate
    it over the network. A system configured as a usbip
    server might be similarly vulnerable to physically
    present users.

  - CVE-2016-3961 / XSA-174
    Vitaly Kuznetsov of Red Hat discovered that Linux
    allowed the use of hugetlbfs on x86 (i386 and amd64)
    systems even when running as a Xen paravirtualised (PV)
    guest, although Xen does not support huge pages. This
    allowed users with access to /dev/hugepages to cause a
    denial of service (crash) in the guest.

  - CVE-2016-4470
    David Howells of Red Hat discovered that a local user
    can trigger a flaw in the Linux kernel's handling of key
    lookups in the keychain subsystem, leading to a denial
    of service (crash) or possibly to privilege escalation.

  - CVE-2016-4482, CVE-2016-4485, CVE-2016-4486,
    CVE-2016-4569, CVE-2016-4578, CVE-2016-4580,
    CVE-2016-5243, CVE-2016-5244

    Kangjie Lu reported that the USB devio, llc, rtnetlink,
    ALSA timer, x25, tipc, and rds facilities leaked
    information from the kernel stack.

  - CVE-2016-4565
    Jann Horn of Google Project Zero reported that various
    components in the InfiniBand stack implemented unusual
    semantics for the write() operation. On a system with
    InfiniBand drivers loaded, local users could use this
    for denial of service or privilege escalation.

  - CVE-2016-4581
    Tycho Andersen discovered that in some situations the
    Linux kernel did not handle propagated mounts correctly.
    A local user can take advantage of this flaw to cause a
    denial of service (system crash).

  - CVE-2016-4805
    Baozeng Ding discovered a use-after-free in the generic
    PPP layer in the Linux kernel. A local user can take
    advantage of this flaw to cause a denial of service
    (system crash), or potentially escalate their
    privileges.

  - CVE-2016-4913
    Al Viro found that the ISO9660 filesystem implementation
    did not correctly count the length of certain invalid
    name entries. Reading a directory containing such name
    entries would leak information from kernel memory. Users
    permitted to mount disks or disk images could use this
    to obtain sensitive information.

  - CVE-2016-4997 / CVE-2016-4998
    Jesse Hertz and Tim Newsham discovered that missing
    input sanitising in Netfilter socket handling may result
    in denial of service. Debian disables unprivileged user
    namespaces by default, if locally enabled with the
    kernel.unprivileged_userns_clone sysctl, this also
    allows privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-3136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-3137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-3138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-3140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-3070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-3134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-3156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-3157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-3672"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-3951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-3955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-3961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3607"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the stable distribution (jessie), these problems have been fixed
in version 3.16.7-ckt25-2+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-x86", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-586", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-686-pae", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-amd64", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armel", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armhf", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-i386", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-amd64", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp-lpae", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-common", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-ixp4xx", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-kirkwood", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-orion5x", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-versatile", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-586", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae-dbg", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64-dbg", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp-lpae", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-ixp4xx", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-kirkwood", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-orion5x", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-versatile", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-9", reference:"3.16.7-ckt25-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-9-amd64", reference:"3.16.7-ckt25-2+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
