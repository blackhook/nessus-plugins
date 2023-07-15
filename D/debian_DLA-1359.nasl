#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1359-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109284);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-17742", "CVE-2018-6914", "CVE-2018-8777", "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780");

  script_name(english:"Debian DLA-1359-1 : ruby1.8 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were found in the interpreter for the Ruby
language. The Common Vulnerabilities and Exposures project identifies
the following issues :

CVE-2017-17742

Aaron Patterson reported that WEBrick bundled with Ruby was vulnerable
to an HTTP response splitting vulnerability. It was possible for an
attacker to inject fake HTTP responses if a script accepted an
external input and output it without modifications.

CVE-2018-6914

ooooooo_q discovered a directory traversal vulnerability in the
Dir.mktmpdir method in the tmpdir library. It made it possible for
attackers to create arbitrary directories or files via a .. (dot dot)
in the prefix argument.

CVE-2018-8777

Eric Wong reported an out-of-memory DoS vulnerability related to a
large request in WEBrick bundled with Ruby.

CVE-2018-8778

aerodudrizzt found a buffer under-read vulnerability in the Ruby
String#unpack method. If a big number was passed with the specifier @,
the number was treated as a negative value, and an out-of-buffer read
occurred. Attackers could read data on heaps if an script accepts an
external input as the argument of String#unpack.

CVE-2018-8779

ooooooo_q reported that the UNIXServer.open and UNIXSocket.open
methods of the socket library bundled with Ruby did not check for NUL
bytes in the path argument. The lack of check made the methods
vulnerable to unintentional socket creation and unintentional socket
access.

CVE-2018-8780

ooooooo_q discovered an unintentional directory traversal in some
methods in Dir, by the lack of checking for NUL bytes in their
parameter.

For Debian 7 'Wheezy', these problems have been fixed in version
1.8.7.358-7.1+deb7u6.

We recommend that you upgrade your ruby1.8 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/04/msg00024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ruby1.8"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libruby1.8-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtcltk-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ri1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.8-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.8-full");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"libruby1.8", reference:"1.8.7.358-7.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libruby1.8-dbg", reference:"1.8.7.358-7.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libtcltk-ruby1.8", reference:"1.8.7.358-7.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"ri1.8", reference:"1.8.7.358-7.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.8", reference:"1.8.7.358-7.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.8-dev", reference:"1.8.7.358-7.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.8-examples", reference:"1.8.7.358-7.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.8-full", reference:"1.8.7.358-7.1+deb7u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
