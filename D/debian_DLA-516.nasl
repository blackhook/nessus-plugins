#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-516-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91687);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-0821", "CVE-2016-1583", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2187", "CVE-2016-3134", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3140", "CVE-2016-3157", "CVE-2016-3672", "CVE-2016-3951", "CVE-2016-3955", "CVE-2016-3961", "CVE-2016-4482", "CVE-2016-4485", "CVE-2016-4486", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4580", "CVE-2016-4913", "CVE-2016-5243", "CVE-2016-5244");

  script_name(english:"Debian DLA-516-1 : linux security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the CVEs described below.

CVE-2016-0821

Solar Designer noted that the list 'poisoning' feature, intended to
mitigate the effects of bugs in list manipulation in the kernel, used
poison values within the range of virtual addresses that can be
allocated by user processes.

CVE-2016-1583

Jann Horn of Google Project Zero reported that the eCryptfs filesystem
could be used together with the proc filesystem to cause a kernel
stack overflow. If the ecryptfs-utils package was installed, local
users could exploit this, via the mount.ecryptfs_private program, for
denial of service (crash) or possibly for privilege escalation.

CVE-2016-2184, CVE-2016-2185, CVE-2016-2186, CVE-2016-2187,
CVE-2016-3136, CVE-2016-3137, CVE-2016-3138, CVE-2016-3140

Ralf Spenneberg of OpenSource Security reported that various USB
drivers do not sufficiently validate USB descriptors. This allowed a
physically present user with a specially designed USB device to cause
a denial of service (crash). Not all the drivers have yet been fixed.

CVE-2016-3134

The Google Project Zero team found that the netfilter subsystem does
not sufficiently validate filter table entries. A user with the
CAP_NET_ADMIN capability could use this for denial of service (crash)
or possibly for privilege escalation.

CVE-2016-3157 / XSA-171

Andy Lutomirski discovered that the x86_64 (amd64) task switching
implementation did not correctly update the I/O permission level when
running as a Xen paravirtual (PV) guest. In some configurations this
would allow local users to cause a denial of service (crash) or to
escalate their privileges within the guest.

CVE-2016-3672

Hector Marco and Ismael Ripoll noted that it was still possible to
disable Address Space Layout Randomisation (ASLR) for x86_32 (i386)
programs by removing the stack resource limit. This made it easier for
local users to exploit security flaws in programs that have the setuid
or setgid flag set.

CVE-2016-3951

It was discovered that the cdc_ncm driver would free memory
prematurely if certain errors occurred during its initialisation. This
allowed a physically present user with a specially designed USB device
to cause a denial of service (crash) or possibly to escalate their
privileges.

CVE-2016-3955

Ignat Korchagin reported that the usbip subsystem did not check the
length of data received for a USB buffer. This allowed denial of
service (crash) or privilege escalation on a system configured as a
usbip client, by the usbip server or by an attacker able to
impersonate it over the network. A system configured as a usbip server
might be similarly vulnerable to physically present users.

CVE-2016-3961 / XSA-174

Vitaly Kuznetsov of Red Hat discovered that Linux allowed use of
hugetlbfs on x86 (i386 and amd64) systems even when running as a Xen
paravirtualised (PV) guest, although Xen does not support huge pages.
This allowed users with access to /dev/hugepages to cause a denial of
service (crash) in the guest.

CVE-2016-4482, CVE-2016-4485, CVE-2016-4486, CVE-2016-4569,
CVE-2016-4578, CVE-2016-4580, CVE-2016-5243, CVE-2016-5244

Kangjie Lu reported that the USB devio, llc, rtnetlink, ALSA timer,
x25, tipc, and rds facilities leaked information from the kernel
stack.

CVE-2016-4565

Jann Horn of Google Project Zero reported that various components in
the InfiniBand stack implemented unusual semantics for the write()
operation. On a system with InfiniBand drivers loaded, local users
could use this for denial of service or privilege escalation.

CVE-2016-4913

Al Viro found that the ISO9660 filesystem implementation did not
correctly count the length of certain invalid name entries. Reading a
directory containing such name entries would leak information from
kernel memory. Users permitted to mount disks or disk images could use
this to obtain sensitive information.

For Debian 7 'Wheezy', these problems have been fixed in version
3.2.81-1.

This update also fixes bug #627782, which caused data corruption in
some applications running on an aufs filesystem, and includes many
other bug fixes from upstream stable updates 3.2.79, 3.2.80 and
3.2.81.

For Debian 8 'Jessie', these problems will be fixed soon.

We recommend that you upgrade your linux packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/06/msg00018.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected linux package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/20");
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
if (deb_check(release:"7.0", prefix:"linux", reference:"3.2.81-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
