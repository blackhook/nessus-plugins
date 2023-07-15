#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2056-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132593);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-2056-1 : waitress security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was a HTTP request smuggling
vulnerability in waitress, pure-Python WSGI server.

If a proxy server is used in front of waitress, an invalid request may
be sent by an attacker that bypasses the front-end and is parsed
differently by waitress leading to a potential for request smuggling.

Specially crafted requests containing special whitespace characters in
the Transfer-Encoding header would get parsed by Waitress as being a
chunked request, but a front-end server would use the Content-Length
instead as the Transfer-Encoding header is considered invalid due to
containing invalid characters. If a front-end server does HTTP
pipelining to a backend Waitress server this could lead to HTTP
request splitting which may lead to potential cache poisoning or
information disclosure.

For Debian 8 'Jessie', this issue has been fixed in waitress version
0.8.9-2+deb8u1.

We recommend that you upgrade your waitress packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/01/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/waitress"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-waitress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-waitress-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-waitress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/02");
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
if (deb_check(release:"8.0", prefix:"python-waitress", reference:"0.8.9-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"python-waitress-doc", reference:"0.8.9-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"python3-waitress", reference:"0.8.9-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
