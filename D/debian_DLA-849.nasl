#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-849-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97640);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-9588", "CVE-2017-2636", "CVE-2017-5669", "CVE-2017-5986", "CVE-2017-6214", "CVE-2017-6345", "CVE-2017-6346", "CVE-2017-6348", "CVE-2017-6353");

  script_name(english:"Debian DLA-849-1 : linux security update");
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

CVE-2016-9588

Jim Mattson discovered that the KVM implementation for Intel x86
processors does not properly handle #BP and #OF exceptions in an L2
(nested) virtual machine. A local attacker in an L2 guest VM can take
advantage of this flaw to cause a denial of service for the L1 guest
VM.

CVE-2017-2636

Alexander Popov discovered a race condition flaw in the n_hdlc line
discipline that can lead to a double free. A local unprivileged user
can take advantage of this flaw for privilege escalation. On systems
that do not already have the n_hdlc module loaded, this can be
mitigated by disabling it: echo >> /etc/modprobe.d/disable-n_hdlc.conf
install n_hdlc false

CVE-2017-5669

Gareth Evans reported that privileged users can map memory at address
0 through the shmat() system call. This could make it easier to
exploit other kernel security vulnerabilities via a set-UID program.

CVE-2017-5986

Alexander Popov reported a race condition in the SCTP implementation
that can be used by local users to cause a denial of service (crash).
The initial fix for this was incorrect and introduced further security
issues (CVE-2017-6353). This update includes a later fix that avoids
those. On systems that do not already have the sctp module loaded,
this can be mitigated by disabling it: echo >>
/etc/modprobe.d/disable-sctp.conf install sctp false

CVE-2017-6214

Dmitry Vyukov reported a bug in the TCP implementation's handling of
urgent data in the splice() system call. This can be used by a remote
attacker for denial of service (hang) against applications that read
from TCP sockets with splice().

CVE-2017-6345

Andrey Konovalov reported that the LLC type 2 implementation
incorrectly assigns socket buffer ownership. This might be usable by a
local user to cause a denial of service (memory corruption or crash)
or privilege escalation. On systems that do not already have the llc2
module loaded, this can be mitigated by disabling it: echo >>
/etc/modprobe.d/disable-llc2.conf install llc2 false

CVE-2017-6346

Dmitry Vyukov reported a race condition in the raw packet (af_packet)
fanout feature. Local users with the CAP_NET_RAW capability (in any
user namespace) can use this for denial of service and possibly for
privilege escalation.

CVE-2017-6348

Dmitry Vyukov reported that the general queue implementation in the
IrDA subsystem does not properly manage multiple locks, possibly
allowing local users to cause a denial of service (deadlock) via
crafted operations on IrDA devices.

For Debian 7 'Wheezy', these problems have been fixed in version
3.2.86-1.

For Debian 8 'Jessie', these problems have been fixed in version
3.16.39-1+deb8u2.

We recommend that you upgrade your linux packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00007.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected linux package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/10");
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
if (deb_check(release:"7.0", prefix:"linux", reference:"3.2.86-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
