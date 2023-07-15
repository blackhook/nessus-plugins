#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1200-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105116);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-10208", "CVE-2017-1000407", "CVE-2017-12190", "CVE-2017-13080", "CVE-2017-14051", "CVE-2017-15115", "CVE-2017-15265", "CVE-2017-15299", "CVE-2017-15649", "CVE-2017-15868", "CVE-2017-16525", "CVE-2017-16527", "CVE-2017-16529", "CVE-2017-16531", "CVE-2017-16532", "CVE-2017-16533", "CVE-2017-16535", "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16643", "CVE-2017-16649", "CVE-2017-16939", "CVE-2017-8824", "CVE-2017-8831");
  script_xref(name:"IAVA", value:"2017-A-0310");

  script_name(english:"Debian DLA-1200-1 : linux security update (KRACK)");
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

CVE-2016-10208

Sergej Schumilo and Ralf Spenneberg discovered that a crafted ext4
filesystem could trigger memory corruption when it is mounted. A user
that can provide a device or filesystem image to be mounted could use
this for denial of service (crash or data corruption) or possibly for
privilege escalation.

CVE-2017-8824

Mohamed Ghannam discovered that the DCCP implementation did not
correctly manage resources when a socket is disconnected and
reconnected, potentially leading to a use-after-free. A local user
could use this for denial of service (crash or data corruption) or
possibly for privilege escalation. On systems that do not already have
the dccp module loaded, this can be mitigated by disabling it: echo >>
/etc/modprobe.d/disable-dccp.conf install dccp false

CVE-2017-8831

Pengfei Wang discovered that the saa7164 video capture driver re-reads
data from a PCI device after validating it. A physically present user
able to attach a specially designed PCI device could use this for
privilege escalation.

CVE-2017-12190

Vitaly Mayatskikh discovered that the block layer did not correctly
count page references for raw I/O from user-space. This can be
exploited by a guest VM with access to a host SCSI device for denial
of service (memory exhaustion) or potentially for privilege
escalation.

CVE-2017-13080

A vulnerability was found in the WPA2 protocol that could lead to
reinstallation of the same Group Temporal Key (GTK), which
substantially reduces the security of wifi encryption. This is one of
the issues collectively known as 'KRACK'.

Updates to GTKs are usually handled by the wpa package,
where this issue was already fixed (DLA-1150-1). However,
some wifi devices can remain active and update GTKs
autonomously while the system is suspended. The kernel must
also check for and ignore key reinstallation.

CVE-2017-14051

'shqking' reported that the qla2xxx SCSI host driver did not correctly
validate I/O to the 'optrom' sysfs attribute of the devices it
creates. This is unlikely to have any security impact.

CVE-2017-15115

Vladis Dronov reported that the SCTP implementation did not correctly
handle 'peel-off' of an association to another net namespace. This
leads to a use-after-free, which a local user can exploit for denial
of service (crash or data corruption) or possibly for privilege
escalation. On systems that do not already have the sctp module
loaded, this can be mitigated by disabling it: echo >>
/etc/modprobe.d/disable-sctp.conf install sctp false

CVE-2017-15265

Michael23 Yu reported a race condition in the ALSA sequencer subsystem
involving creation and deletion of ports, which could lead to a
use-after-free. A local user with access to an ALSA sequencer device
can use this for denial of service (crash or data loss) or possibly
for privilege escalation.

CVE-2017-15299

Eric Biggers discovered that the KEYS subsystem did not correctly
handle update of an uninstantiated key, leading to a null dereference.
A local user can use this for denial of service (crash).

CVE-2017-15649

'nixioaming' reported a race condition in the packet socket
(AF_PACKET) implementation involving rebinding to a fanout group,
which could lead to a use-after-free. A local user with the
CAP_NET_RAW capability can use this for denial of service (crash or
data corruption) or possibly for privilege escalation.

CVE-2017-15868

Al Viro found that the Bluebooth Network Encapsulation Protocol (BNEP)
implementation did not validate the type of the second socket passed
to the BNEPCONNADD ioctl(), which could lead to memory corruption. A
local user with the CAP_NET_ADMIN capability can use this for denial
of service (crash or data corruption) or possibly for privilege
escalation.

CVE-2017-16525

Andrey Konovalov reported that the USB serial console implementation
did not correctly handle disconnection of unusual serial devices,
leading to a use-after-free. A similar issue was found in the case
where setup of a serial console fails. A physically present user with
a specially designed USB device can use this to cause a denial of
service (crash or data corruption) or possibly for privilege
escalation.

CVE-2017-16527

Andrey Konovalov reported that the USB sound mixer driver did not
correctly cancel I/O in case it failed to probe a device, which could
lead to a use-after-free. A physically present user with a specially
designed USB device can use this to cause a denial of service (crash
or data corruption) or possibly for privilege escalation.

CVE-2017-16529

Andrey Konovalov reported that the USB sound driver did not fully
validate descriptor lengths, which could lead to a buffer over-read. A
physically present user with a specially designed USB device may be
able to use this to cause a denial of service (crash).

CVE-2017-16531

Andrey Konovalov reported that the USB core did not validate IAD
lengths, which could lead to a buffer over-read. A physically present
user with a specially designed USB device may be able to use this to
cause a denial of service (crash).

CVE-2017-16532

Andrey Konovalov reported that the USB test driver did not correctly
handle devices with specific combinations of endpoints. A physically
present user with a specially designed USB device can use this to
cause a denial of service (crash).

CVE-2017-16533

Andrey Konovalov reported that the USB HID driver did not fully
validate descriptor lengths, which could lead to a buffer over-read. A
physically present user with a specially designed USB device may be
able to use this to cause a denial of service (crash).

CVE-2017-16535

Andrey Konovalov reported that the USB core did not validate BOS
descriptor lengths, which could lead to a buffer over-read. A
physically present user with a specially designed USB device may be
able to use this to cause a denial of service (crash).

CVE-2017-16536

Andrey Konovalov reported that the cx231xx video capture driver did
not fully validate the device endpoint configuration, which could lead
to a null dereference. A physically present user with a specially
designed USB device can use this to cause a denial of service (crash).

CVE-2017-16537

Andrey Konovalov reported that the imon RC driver did not fully
validate the device interface configuration, which could lead to a
null dereference. A physically present user with a specially designed
USB device can use this to cause a denial of service (crash).

CVE-2017-16643

Andrey Konovalov reported that the gtco tablet driver did not fully
validate descriptor lengths, which could lead to a buffer over-read. A
physically present user with a specially designed USB device may be
able to use this to cause a denial of service (crash).

CVE-2017-16649

Bj&oslash;rn Mork found that the cdc_ether network driver did not
validate the device's maximum segment size, potentially leading to a
division by zero. A physically present user with a specially designed
USB device can use this to cause a denial of service (crash).

CVE-2017-16939

Mohamed Ghannam reported (through Beyond Security's SecuriTeam Secure
Disclosure program) that the IPsec (xfrm) implementation did not
correctly handle some failure cases when dumping policy information
through netlink. A local user with the CAP_NET_ADMIN capability can
use this for denial of service (crash or data corruption) or possibly
for privilege escalation.

CVE-2017-1000407

Andrew Honig reported that the KVM implementation for Intel processors
allowed direct access to host I/O port 0x80, which is not generally
safe. On some systems this allows a guest VM to cause a denial of
service (crash) of the host.

For Debian 7 'Wheezy', these problems have been fixed in version
3.2.96-2. This version also includes bug fixes from upstream versions
up to and including 3.2.96. It also fixes some regressions caused by
the fix for CVE-2017-1000364, which was included in DLA-993-1.

We recommend that you upgrade your linux packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/12/msg00004.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected linux package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (deb_check(release:"7.0", prefix:"linux", reference:"3.2.96-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
