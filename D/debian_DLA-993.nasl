#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-993-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100876);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-1000364", "CVE-2017-7487", "CVE-2017-7645", "CVE-2017-7895", "CVE-2017-8890", "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9242");

  script_name(english:"Debian DLA-993-2 : linux regression update (Stack Clash)");
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

CVE-2017-7487

Li Qiang reported a reference counter leak in the ipxitf_ioctl
function which may result into a use-after-free vulnerability,
triggerable when a IPX interface is configured.

CVE-2017-7645

Tuomas Haanpaa and Matti Kamunen from Synopsys Ltd discovered that the
NFSv2 and NFSv3 server implementations are vulnerable to an
out-of-bounds memory access issue while processing arbitrarily long
arguments sent by NFSv2/NFSv3 PRC clients, leading to a denial of
service.

CVE-2017-7895

Ari Kauppi from Synopsys Ltd discovered that the NFSv2 and NFSv3
server implementations do not properly handle payload bounds checking
of WRITE requests. A remote attacker with write access to a NFS mount
can take advantage of this flaw to read chunks of arbitrary memory
from both kernel-space and user-space.

CVE-2017-8890

It was discovered that the net_csk_clone_lock() function allows a
remote attacker to cause a double free leading to a denial of service
or potentially have other impact.

CVE-2017-8924

Johan Hovold found that the io_ti USB serial driver could leak
sensitive information if a malicious USB device was connected.

CVE-2017-8925

Johan Hovold found a reference counter leak in the omninet USB serial
driver, resulting in a use-after-free vulnerability. This can be
triggered by a local user permitted to open tty devices.

CVE-2017-9074

Andrey Konovalov reported that the IPv6 fragmentation implementation
could read beyond the end of a packet buffer. A local user or guest VM
might be able to use this to leak sensitive information or to cause a
denial of service (crash).

CVE-2017-9075

Andrey Konovalov reported that the SCTP/IPv6 implementation wrongly
initialised address lists on connected sockets, resulting in a
use-after-free vulnerability, a similar issue to CVE-2017-8890. This
can be triggered by any local user.

CVE-2017-9076 / CVE-2017-9077 Cong Wang found that the TCP/IPv6 and
DCCP/IPv6 implementations wrongly initialised address lists on
connected sockets, a similar issue to CVE-2017-9075.

CVE-2017-9242

Andrey Konovalov reported a packet buffer overrun in the IPv6
implementation. A local user could use this for denial of service
(memory corruption; crash) and possibly for privilege escalation.

CVE-2017-1000364

The Qualys Research Labs discovered that the size of the stack guard
page is not sufficiently large. The stack-pointer can jump over the
guard-page and moving from the stack into another memory region
without accessing the guard-page. In this case no page-fault exception
is raised and the stack extends into the other memory region. An
attacker can exploit this flaw for privilege escalation.

The default stack gap protection is set to 256 pages and can
be configured via the stack_guard_gap kernel parameter on
the kernel command line.

Further details can be found at
https://www.qualys.com/2017/06/19/stack-clash/stack-clash.tx
t

For Debian 7 'Wheezy', this problem has been fixed in version
3.2.89-2.

For Debian 8 'Jessie', this problem has been fixed in version
3.16.43-2+deb8u2.

For Debian 9 'Stretch', this problem has been fixed in version
4.9.30-2+deb9u2.

We recommend that you upgrade your linux packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/06/msg00033.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected linux package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'rsh_stack_clash_priv_esc.rb');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (deb_check(release:"7.0", prefix:"linux", reference:"3.2.89-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
