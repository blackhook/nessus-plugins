#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2394-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(141136);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/07");

  script_cve_id("CVE-2020-15049", "CVE-2020-15810", "CVE-2020-15811", "CVE-2020-24606");

  script_name(english:"Debian DLA-2394-1 : squid3 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several security vulnerabilities have been discovered in Squid, a
high- performance proxy caching server for web clients.

CVE-2020-15049

An issue was discovered in http/ContentLengthInterpreter.cc in Squid.
A Request Smuggling and Poisoning attack can succeed against the HTTP
cache. The client sends an HTTP request with a Content- Length header
containing '+\ '-' or an uncommon shell whitespace character prefix to
the length field-value. This update also includes several other
improvements to the HttpHeader parsing code.

CVE-2020-15810 and CVE-2020-15811

Due to incorrect data validation, HTTP Request Smuggling attacks may
succeed against HTTP and HTTPS traffic. This leads to cache poisoning
and allows any client, including browser scripts, to bypass local
security and poison the proxy cache and any downstream caches with
content from an arbitrary source. When configured for relaxed header
parsing (the default), Squid relays headers containing whitespace
characters to upstream servers. When this occurs as a prefix to a
Content-Length header, the frame length specified will be ignored by
Squid (allowing for a conflicting length to be used from another
Content-Length header) but relayed upstream.

CVE-2020-24606

Squid allows a trusted peer to perform Denial of Service by consuming
all available CPU cycles during handling of a crafted Cache Digest
response message. This only occurs when cache_peer is used with the
cache digests feature. The problem exists because
peerDigestHandleReply() livelocking in peer_digest.cc mishandles EOF.

For Debian 9 stretch, these problems have been fixed in version
3.5.23-5+deb9u5.

We recommend that you upgrade your squid3 packages.

For the detailed security status of squid3 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/squid3

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/10/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/squid3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/squid3"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15049");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-purge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squidclient");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"squid", reference:"3.5.23-5+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"squid-cgi", reference:"3.5.23-5+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"squid-common", reference:"3.5.23-5+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"squid-dbg", reference:"3.5.23-5+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"squid-purge", reference:"3.5.23-5+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"squid3", reference:"3.5.23-5+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"squidclient", reference:"3.5.23-5+deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
