#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2559-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(146504);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2011-5325", "CVE-2015-9261", "CVE-2016-2147", "CVE-2016-2148", "CVE-2017-15873", "CVE-2017-16544", "CVE-2018-1000517");

  script_name(english:"Debian DLA-2559-1 : busybox security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Busybox, utility programs for small and embedded systems, was affected
by several security vulnerabilities. The Common Vulnerabilities and
Exposures project identifies the following issues.

CVE-2011-5325

A path traversal vulnerability was found in Busybox implementation of
tar. tar will extract a symlink that points outside of the current
working directory and then follow that symlink when extracting other
files. This allows for a directory traversal attack when extracting
untrusted tarballs.

CVE-2013-1813

When device node or symlink in /dev should be created inside
2-or-deeper subdirectory (/dev/dir1/dir2.../node), the intermediate
directories are created with incorrect permissions.

CVE-2014-4607

An integer overflow may occur when processing any variant of a
'literal run' in the lzo1x_decompress_safe function. Each of these
three locations is subject to an integer overflow when processing zero
bytes. This exposes the code that copies literals to memory
corruption.

CVE-2014-9645

The add_probe function in modutils/modprobe.c in BusyBox allows local
users to bypass intended restrictions on loading kernel modules via a
/ (slash) character in a module name, as demonstrated by an 'ifconfig
/usbserial up' command or a 'mount -t /snd_pcm none /' command.

CVE-2016-2147

Integer overflow in the DHCP client (udhcpc) in BusyBox allows remote
attackers to cause a denial of service (crash) via a malformed
RFC1035-encoded domain name, which triggers an out-of-bounds heap
write.

CVE-2016-2148

Heap-based buffer overflow in the DHCP client (udhcpc) in BusyBox
allows remote attackers to have unspecified impact via vectors
involving OPTION_6RD parsing.

CVE-2017-15873

The get_next_block function in archival/libarchive
/decompress_bunzip2.c in BusyBox has an Integer Overflow that may lead
to a write access violation.

CVE-2017-16544

In the add_match function in libbb/lineedit.c in BusyBox, the tab
autocomplete feature of the shell, used to get a list of filenames in
a directory, does not sanitize filenames and results in executing any
escape sequence in the terminal. This could potentially result in code
execution, arbitrary file writes, or other attacks.

CVE-2018-1000517

BusyBox contains a Buffer Overflow vulnerability in Busybox wget that
can result in a heap-based buffer overflow. This attack appears to be
exploitable via network connectivity.

CVE-2015-9621

Unziping a specially crafted zip file results in a computation of an
invalid pointer and a crash reading an invalid address.

For Debian 9 stretch, these problems have been fixed in version
1:1.22.0-19+deb9u1.

We recommend that you upgrade your busybox packages.

For the detailed security status of busybox please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/busybox

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/02/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/busybox"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/busybox"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:busybox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:busybox-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:busybox-syslogd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:busybox-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udhcpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udhcpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"busybox", reference:"1:1.22.0-19+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"busybox-static", reference:"1:1.22.0-19+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"busybox-syslogd", reference:"1:1.22.0-19+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"busybox-udeb", reference:"1:1.22.0-19+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"udhcpc", reference:"1:1.22.0-19+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"udhcpd", reference:"1:1.22.0-19+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
