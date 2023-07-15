#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1568-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118753);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-7141", "CVE-2016-7167", "CVE-2016-9586", "CVE-2018-16839", "CVE-2018-16842");

  script_name(english:"Debian DLA-1568-1 : curl security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in cURL, an URL transfer
library.

CVE-2016-7141

When built with NSS and the libnsspem.so library is available at
runtime, allows an remote attacker to hijack the authentication of a
TLS connection by leveraging reuse of a previously loaded client
certificate from file for a connection for which no certificate has
been set, a different vulnerability than CVE-2016-5420.

CVE-2016-7167

Multiple integer overflows in the (1) curl_escape, (2)
curl_easy_escape, (3) curl_unescape, and (4) curl_easy_unescape
functions in libcurl allow attackers to have unspecified impact via a
string of length 0xffffffff, which triggers a heap-based buffer
overflow.

CVE-2016-9586

Curl is vulnerable to a buffer overflow when doing a large floating
point output in libcurl's implementation of the printf() functions. If
there are any applications that accept a format string from the
outside without necessary input filtering, it could allow remote
attacks.

CVE-2018-16839

Curl is vulnerable to a buffer overrun in the SASL authentication code
that may lead to denial of service.

CVE-2018-16842

Curl is vulnerable to a heap-based buffer over-read in the
tool_msgs.c:voutf() function that may result in information exposure
and denial of service.

For Debian 8 'Jessie', these problems have been fixed in version
7.38.0-4+deb8u13.

We recommend that you upgrade your curl packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/curl"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-gnutls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-nss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-openssl-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/07");
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
if (deb_check(release:"8.0", prefix:"curl", reference:"7.38.0-4+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3", reference:"7.38.0-4+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3-dbg", reference:"7.38.0-4+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3-gnutls", reference:"7.38.0-4+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3-nss", reference:"7.38.0-4+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-doc", reference:"7.38.0-4+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-gnutls-dev", reference:"7.38.0-4+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-nss-dev", reference:"7.38.0-4+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-openssl-dev", reference:"7.38.0-4+deb8u13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
