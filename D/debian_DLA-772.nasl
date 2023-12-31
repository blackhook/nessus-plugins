#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-772-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96188);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-6704", "CVE-2015-1350", "CVE-2015-8962", "CVE-2015-8963", "CVE-2015-8964", "CVE-2016-10088", "CVE-2016-7097", "CVE-2016-7910", "CVE-2016-7911", "CVE-2016-7915", "CVE-2016-8399", "CVE-2016-8633", "CVE-2016-8645", "CVE-2016-8655", "CVE-2016-9178", "CVE-2016-9555", "CVE-2016-9576", "CVE-2016-9756", "CVE-2016-9793", "CVE-2016-9794");

  script_name(english:"Debian DLA-772-1 : linux security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2012-6704, CVE-2016-9793

Eric Dumazet found that a local user with CAP_NET_ADMIN capability
could set a socket's buffer size to be negative, leading to a denial
of service or other security impact. Additionally, in kernel versions
prior to 3.5, any user could do this if sysctl net.core.rmem_max was
changed to a very large value.

CVE-2015-1350 / #770492

Ben Harris reported that local users could remove set-capability
attributes from any file visible to them, allowing a denial of
service.

CVE-2015-8962

Calvin Owens fouund that removing a SCSI device while it was being
accessed through the SCSI generic (sg) driver led to a double- free,
possibly causing a denial of service (crash or memory corruption) or
privilege escalation. This could be exploited by local users with
permision to access a SCSI device node.

CVE-2015-8963

Sasha Levin reported that hot-unplugging a CPU resulted in a
use-after-free by the performance events (perf) subsystem, possibly
causing a denial of service (crash or memory corruption) or privilege
escalation. This could by exploited by any local user.

CVE-2015-8964

It was found that the terminal/serial (tty) subsystem did not reliably
reset the terminal buffer state when the terminal line discipline was
changed. This could allow a local user with access to a terminal
device to read sensitive information from kernel memory.

CVE-2016-7097

Jan Kara found that changing the POSIX ACL of a file never cleared its
set-group-ID flag, which should be done if the user changing it is not
a member of the group-owner. In some cases, this would allow the
user-owner of an executable to gain the privileges of the group-owner.

CVE-2016-7910

Vegard Nossum discovered that a memory allocation failure while
handling a read of /proc/diskstats or /proc/partitions could lead to a
use-after-free, possibly causing a denial of service (crash or memory
corruption) or privilege escalation.

CVE-2016-7911

Dmitry Vyukov reported that a race between ioprio_get() and
ioprio_set() system calls could result in a use-after-free, possibly
causing a denial of service (crash) or leaking sensitive information.

CVE-2016-7915

Benjamin Tissoires found that HID devices could trigger an out-of-
bounds memory access in the HID core. A physically present user could
possibly use this for denial of service (crash) or to leak sensitive
information.

CVE-2016-8399

Qidan He reported that the IPv4 ping socket implementation did not
validate the length of packets to be sent. A user with permisson to
use ping sockets could cause an out-of-bounds read, possibly resulting
in a denial of service or information leak. However, on Debian systems
no users have permission to create ping sockets by default.

CVE-2016-8633

Eyal Itkin reported that the IP-over-Firewire driver (firewire-net)
did not validate the offset or length in link-layer fragmentation
headers. This allowed a remote system connected by Firewire to write
to memory after a packet buffer, leading to a denial of service
(crash) or remote code execution.

CVE-2016-8645

Marco Grassi reported that if a socket filter (BPF program) attached
to a TCP socket truncates or removes the TCP header, this could cause
a denial of service (crash). This was exploitable by any local user.

CVE-2016-8655

Philip Pettersson found that the implementation of packet sockets
(AF_PACKET family) had a race condition between enabling a transmit
ring buffer and changing the version of buffers used, which could
result in a use-after-free. A local user with the CAP_NET_ADMIN
capability could exploit this for privilege escalation.

CVE-2016-9178

Al Viro found that a failure to read data from user memory might lead
to a information leak on the x86 architecture (amd64 or i386).

CVE-2016-9555

Andrey Konovalov reported that the SCTP implementation does not
validate 'out of the blue' packet chunk lengths early enough. A remote
system able could use this to cause a denial of service (crash) or
other security impact for systems using SCTP.

CVE-2016-9576, CVE-2016-10088

Dmitry Vyukov reported that using splice() with the SCSI generic
driver led to kernel memory corruption. Local users with permision to
access a SCSI device node could exploit this for privilege escalation.

CVE-2016-9756

Dmitry Vyukov reported that KVM for the x86 architecture (amd64 or
i386) did not correctly handle the failure of certain instructions
that require software emulation on older processors. This could be
exploited by guest systems to leak sensitive information or for denial
of service (log spam).

CVE-2016-9794

Baozeng Ding reported a race condition in the ALSA (sound) subsystem
that could result in a use-after-free. Local users with access to a
PCM sound device could exploit this for denial of service (crash or
memory corruption) or other security impact.

For Debian 7 'Wheezy', these problems have been fixed in version
3.2.84-1. This version also includes bug fixes from upstream version
3.2.84 and updates the PREEMPT_RT featureset to version 3.2.84-rt122.
Finally, this version adds the option to mitigate security issues in
the performance events (perf) subsystem by disabling use by
unprivileged users. This can be done by setting sysctl
kernel.perf_event_paranoid=3.

For Debian 8 'Jessie', these problems have been fixed in version
3.16.39-1 which will be included in the next point release (8.6).

We recommend that you upgrade your linux packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/01/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected linux package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AF_PACKET chocobo_root Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/03");
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
if (deb_check(release:"7.0", prefix:"linux", reference:"3.2.84-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
