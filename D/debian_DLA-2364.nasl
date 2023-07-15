#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2364-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140295);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2019-20444", "CVE-2019-20445", "CVE-2020-11612", "CVE-2020-7238");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Debian DLA-2364-1 : netty security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in netty, a Java NIO
client/server socket framework.

CVE-2019-20444

HttpObjectDecoder.java in Netty before 4.1.44 allows an HTTP header
that lacks a colon, which might be interpreted as a separate header
with an incorrect syntax, or might be interpreted as an 'invalid
fold.'

CVE-2019-20445

HttpObjectDecoder.java in Netty before 4.1.44 allows a Content-Length
header to be accompanied by a second Content-Length header, or by a
Transfer-Encoding header.

CVE-2020-7238

Netty 4.1.43.Final allows HTTP Request Smuggling because it mishandles
Transfer-Encoding whitespace (such as a
[space]Transfer-Encoding:chunked line) and a later Content-Length
header. This issue exists because of an incomplete fix for
CVE-2019-16869.

CVE-2020-11612

The ZlibDecoders in Netty 4.1.x before 4.1.46 allow for unbounded
memory allocation while decoding a ZlibEncoded byte stream. An
attacker could send a large ZlibEncoded byte stream to the Netty
server, forcing the server to allocate all of its free memory to a
single decoder.

For Debian 9 stretch, these problems have been fixed in version
1:4.1.7-2+deb9u2.

We recommend that you upgrade your netty packages.

For the detailed security status of netty please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/netty

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/netty"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/netty"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected libnetty-java package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20445");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnetty-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libnetty-java", reference:"1:4.1.7-2+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
