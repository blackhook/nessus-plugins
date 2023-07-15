#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-609-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93321);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-3857", "CVE-2016-4470", "CVE-2016-5696", "CVE-2016-5829", "CVE-2016-6136", "CVE-2016-6480", "CVE-2016-6828", "CVE-2016-7118");

  script_name(english:"Debian DLA-609-1 : linux security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the CVEs described below.

CVE-2016-3857

Chiachih Wu reported two bugs in the ARM OABI compatibility layer that
can be used by local users for privilege escalation. The OABI
compatibility layer is enabled in all kernel flavours for armel and
armhf.

CVE-2016-4470

Wade Mealing of the Red Hat Product Security Team reported that in
some error cases the KEYS subsystem will dereference an uninitialised
pointer. A local user can use the keyctl() system call for denial of
service (crash) or possibly for privilege escalation.

CVE-2016-5696

Yue Cao, Zhiyun Qian, Zhongjie Wang, Tuan Dao, and Srikanth V.
Krishnamurthy of the University of California, Riverside; and Lisa M.
Marvel of the United States Army Research Laboratory discovered that
Linux's implementation of the TCP Challenge ACK feature results in a
side channel that can be used to find TCP connections between specific
IP addresses, and to inject messages into those connections.

Where a service is made available through TCP, this may
allow remote attackers to impersonate another connected user
to the server or to impersonate the server to another
connected user. In case the service uses a protocol with
message authentication (e.g. TLS or SSH), this vulnerability
only allows denial of service (connection failure). An
attack takes tens of seconds, so short-lived TCP connections
are also unlikely to be vulnerable.

This may be mitigated by increasing the rate limit for TCP
Challenge ACKs so that it is never exceeded: sysctl
net.ipv4.tcp_challenge_ack_limit=1000000000

CVE-2016-5829

Several heap-based buffer overflow vulnerabilities were found in the
hiddev driver, allowing a local user with access to a HID device to
cause a denial of service or potentially escalate their privileges.

CVE-2016-6136

Pengfei Wang discovered that the audit subsystem has a 'double-fetch'
or 'TOCTTOU' bug in its handling of special characters in the name of
an executable. Where audit logging of execve() is enabled, this allows
a local user to generate misleading log messages.

CVE-2016-6480

Pengfei Wang discovered that the aacraid driver for Adaptec RAID
controllers has a 'double-fetch' or 'TOCTTOU' bug in its validation of
'FIB' messages passed through the ioctl() system call. This has no
practical security impact in current Debian releases.

CVE-2016-6828

Marco Grassi reported a 'use-after-free' bug in the TCP
implementation, which can be triggered by local users. The security
impact is unclear, but might include denial of service or privilege
escalation.

CVE-2016-7118

Marcin Szewczyk reported that calling fcntl() on a file descriptor for
a directory on an aufs filesystem would result in am 'oops'. This
allows local users to cause a denial of service. This is a
Debian-specific regression introduced in version 3.2.81-1.

For Debian 7 'Wheezy', these problems have been fixed in version
3.2.81-2. This version also fixes a build failure (bug #827561) for
custom kernels with CONFIG_MODULES disabled, a regression in version
3.2.81-1. It also updates the PREEMPT_RT featureset to version
3.2.81-rt117.

For Debian 8 'Jessie', CVE-2016-3857 has no impact; CVE-2016-4470 and
CVE-2016-5829 were fixed in linux version 3.16.7-ckt25-2+deb8u3 or
earlier; and the remaining issues are fixed in version
3.16.36-1+deb8u1.

We recommend that you upgrade your linux packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/09/msg00002.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected linux package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/06");
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
if (deb_check(release:"7.0", prefix:"linux", reference:"3.2.81-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
