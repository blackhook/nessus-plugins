#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2110-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133814);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-0193", "CVE-2014-3488", "CVE-2019-16869", "CVE-2019-20444", "CVE-2019-20445", "CVE-2020-7238");
  script_bugtraq_id(67182, 68999);

  script_name(english:"Debian DLA-2110-1 : netty-3.9 security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Netty, a Java NIO
client/server socket framework :

CVE-2014-0193

WebSocket08FrameDecoder allows remote attackers to cause a denial of
service (memory consumption) via a TextWebSocketFrame followed by a
long stream of ContinuationWebSocketFrames.

CVE-2014-3488

The SslHandler allows remote attackers to cause a denial of service
(infinite loop and CPU consumption) via a crafted SSLv2Hello message.

CVE-2019-16869

Netty mishandles whitespace before the colon in HTTP headers (such as
a 'Transfer-Encoding : chunked' line), which leads to HTTP request
smuggling.

CVE-2019-20444

HttpObjectDecoder.java allows an HTTP header that lacks a colon, which
might be interpreted as a separate header with an incorrect syntax, or
might be interpreted as an 'invalid fold.'

CVE-2019-20445

HttpObjectDecoder.java allows a Content-Length header to be
accompanied by a second Content-Length header, or by a
Transfer-Encoding header.

CVE-2020-7238

Netty allows HTTP Request Smuggling because it mishandles
Transfer-Encoding whitespace (such as a
[space]Transfer-Encoding:chunked line) and a later Content-Length
header.

For Debian 8 'Jessie', these problems have been fixed in version
3.9.0.Final-1+deb8u1.

We recommend that you upgrade your netty-3.9 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/02/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/netty-3.9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected libnetty-3.9-java package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnetty-3.9-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libnetty-3.9-java", reference:"3.9.0.Final-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
