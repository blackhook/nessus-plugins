#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-922-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99733);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-10200", "CVE-2016-2188", "CVE-2016-9604", "CVE-2017-2647", "CVE-2017-2671", "CVE-2017-5967", "CVE-2017-5970", "CVE-2017-6951", "CVE-2017-7184", "CVE-2017-7261", "CVE-2017-7273", "CVE-2017-7294", "CVE-2017-7308", "CVE-2017-7472", "CVE-2017-7616", "CVE-2017-7618");

  script_name(english:"Debian DLA-922-1 : linux security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or have other
impacts.

CVE-2016-2188

Ralf Spenneberg of OpenSource Security reported that the iowarrior
device driver did not sufficiently validate USB descriptors. This
allowed a physically present user with a specially designed USB device
to cause a denial of service (crash).

CVE-2016-9604

It was discovered that the keyring subsystem allowed a process to set
a special internal keyring as its session keyring. The security impact
in this version of the kernel is unknown.

CVE-2016-10200

Baozeng Ding and Andrey Konovalov reported a race condition in the
L2TP implementation which could corrupt its table of bound sockets. A
local user could use this to cause a denial of service (crash) or
possibly for privilege escalation.

CVE-2017-2647 / CVE-2017-6951

idl3r reported that the keyring subsystem would allow a process to
search for 'dead' keys, causing a NULL pointer dereference. A local
user could use this to cause a denial of service (crash).

CVE-2017-2671

Daniel Jiang discovered a race condition in the ping socket
implementation. A local user with access to ping sockets could use
this to cause a denial of service (crash) or possibly for privilege
escalation. This feature is not accessible to any users by default.

CVE-2017-5967

Xing Gao reported that the /proc/timer_list file showed information
about all processes, not considering PID namespaces. If timer
debugging was enabled by a privileged user, this leaked information to
processes contained in PID namespaces.

CVE-2017-5970

Andrey Konovalov discovered a denial of service flaw in the IPv4
networking code. This can be triggered by a local or remote attacker
if a local UDP or raw socket has the IP_RETOPTS option enabled.

CVE-2017-7184

Chaitin Security Research Lab discovered that the net xfrm subsystem
did not sufficiently validate replay state parameters, allowing a heap
buffer overflow. This can be used by a local user with the
CAP_NET_ADMIN capability for privilege escalation.

CVE-2017-7261

Vladis Dronov and Murray McAllister reported that the vmwgfx driver
did not sufficiently validate rendering surface parameters. In a
VMware guest, this can be used by a local user to cause a denial of
service (crash).

CVE-2017-7273

Benoit Camredon reported that the hid-cypress driver did not
sufficiently validate HID reports. This possibly allowed a physically
present user with a specially designed USB device to cause a denial of
service (crash).

CVE-2017-7294

Li Qiang reported that the vmwgfx driver did not sufficiently validate
rendering surface parameters. In a VMware guest, this can be used by a
local user to cause a denial of service (crash) or possibly for
privilege escalation.

CVE-2017-7308

Andrey Konovalov reported that the packet socket (AF_PACKET)
implementation did not sufficiently validate buffer parameters. This
can be used by a local user with the CAP_NET_RAW capability for
privilege escalation.

CVE-2017-7472

Eric Biggers reported that the keyring subsystem allowed a thread to
create new thread keyrings repeatedly, causing a memory leak. This can
be used by a local user to cause a denial of service (memory
exhaustion).

CVE-2017-7616

Chris Salls reported an information leak in the 32-bit big-endian
compatibility implementations of set_mempolicy() and mbind(). This
does not affect any architecture supported in Debian 7 LTS.

CVE-2017-7618

Sabrina Dubroca reported that the cryptographic hash subsystem does
not correctly handle submission of unaligned data to a device that is
already busy, resulting in infinite recursion. On some systems this
can be used by local users to cause a denial of service (crash).

For Debian 7 'Wheezy', these problems have been fixed in version
3.2.88-1. This version also includes bug fixes from upstream version
3.2.88, and fixes some older security issues in the keyring, packet
socket and cryptographic hash subsystems that do not have CVE IDs.

For Debian 8 'Jessie', most of these problems have been fixed in
version 3.16.43-1 which will be part of the next point release.

We recommend that you upgrade your linux packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00041.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected linux package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AF_PACKET packet_set_ring Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");
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
if (deb_check(release:"7.0", prefix:"linux", reference:"3.2.88-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
