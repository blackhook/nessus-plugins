#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3791. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97357);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-6786", "CVE-2016-6787", "CVE-2016-8405", "CVE-2016-9191", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-2596", "CVE-2017-2618", "CVE-2017-5549", "CVE-2017-5551", "CVE-2017-5897", "CVE-2017-5970", "CVE-2017-6001", "CVE-2017-6074");
  script_xref(name:"DSA", value:"3791");

  script_name(english:"Debian DSA-3791-1 : linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or have other
impacts.

  - CVE-2016-6786 / CVE-2016-6787
    It was discovered that the performance events subsystem
    does not properly manage locks during certain
    migrations, allowing a local attacker to escalate
    privileges. This can be mitigated by disabling
    unprivileged use of performance events:sysctl
    kernel.perf_event_paranoid=3

  - CVE-2016-8405
    Peter Pi of Trend Micro discovered that the frame buffer
    video subsystem does not properly check bounds while
    copying color maps to userspace, causing a heap buffer
    out-of-bounds read, leading to information disclosure.

  - CVE-2016-9191
    CAI Qian discovered that reference counting is not
    properly handled within proc_sys_readdir in the sysctl
    implementation, allowing a local denial of service
    (system hang) or possibly privilege escalation.

  - CVE-2017-2583
    Xiaohan Zhang reported that KVM for amd64 does not
    correctly emulate loading of a null stack selector. This
    can be used by a user in a guest VM for denial of
    service (on an Intel CPU) or to escalate privileges
    within the VM (on an AMD CPU).

  - CVE-2017-2584
    Dmitry Vyukov reported that KVM for x86 does not
    correctly emulate memory access by the SGDT and SIDT
    instructions, which can result in a use-after-free and
    information leak.

  - CVE-2017-2596
    Dmitry Vyukov reported that KVM leaks page references
    when emulating a VMON for a nested hypervisor. This can
    be used by a privileged user in a guest VM for denial of
    service or possibly to gain privileges in the host.

  - CVE-2017-2618
    It was discovered that an off-by-one in the handling of
    SELinux attributes in /proc/pid/attr could result in
    local denial of service.

  - CVE-2017-5549
    It was discovered that the KLSI KL5KUSB105 serial USB
    device driver could log the contents of uninitialised
    kernel memory, resulting in an information leak.

  - CVE-2017-5551
    Jan Kara found that changing the POSIX ACL of a file on
    tmpfs never cleared its set-group-ID flag, which should
    be done if the user changing it is not a member of the
    group-owner. In some cases, this would allow the
    user-owner of an executable to gain the privileges of
    the group-owner.

  - CVE-2017-5897
    Andrey Konovalov discovered an out-of-bounds read flaw
    in the ip6gre_err function in the IPv6 networking code.

  - CVE-2017-5970
    Andrey Konovalov discovered a denial-of-service flaw in
    the IPv4 networking code. This can be triggered by a
    local or remote attacker if a local UDP or raw socket
    has the IP_RETOPTS option enabled.

  - CVE-2017-6001
    Di Shen discovered a race condition between concurrent
    calls to the performance events subsystem, allowing a
    local attacker to escalate privileges. This flaw exists
    because of an incomplete fix of CVE-2016-6786. This can
    be mitigated by disabling unprivileged use of
    performance events: sysctl kernel.perf_event_paranoid=3

  - CVE-2017-6074
    Andrey Konovalov discovered a use-after-free
    vulnerability in the DCCP networking code, which could
    result in denial of service or local privilege
    escalation. On systems that do not already have the dccp
    module loaded, this can be mitigated by disabling
    it:echo >> /etc/modprobe.d/disable-dccp.conf install
    dccp false"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-6786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-6787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-9191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-2583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-2584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-2596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-2618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-6001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-6786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-6074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3791"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the stable distribution (jessie), these problems have been fixed
in version 3.16.39-1+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/24");
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
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-x86", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-586", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-686-pae", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-amd64", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armel", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armhf", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-i386", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-amd64", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp-lpae", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-common", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-ixp4xx", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-kirkwood", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-orion5x", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-versatile", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-586", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae-dbg", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64-dbg", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp-lpae", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-ixp4xx", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-kirkwood", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-orion5x", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-versatile", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-9", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-9-amd64", reference:"3.16.39-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
