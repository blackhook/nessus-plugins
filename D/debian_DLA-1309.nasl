#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1309-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108416);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-1000120", "CVE-2018-1000121", "CVE-2018-1000122");

  script_name(english:"Debian DLA-1309-1 : curl security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were found in cURL, an URL transfer library :

CVE-2018-1000120

Duy Phan Thanh reported that curl could be fooled into writing a zero
byte out of bounds when curl was told to work on an FTP URL, with the
setting to only issue a single CWD command. The issue could be
triggered if the directory part of the URL contained a '%00' sequence.

CVE-2018-1000121

Dario Weisser reported that curl might dereference a near-NULL address
when getting an LDAP URL. A malicious server that sends a particularly
crafted response could made crash applications that allowed LDAP URL
relying on libcurl.

CVE-2018-1000122

OSS-fuzz and Max Dymond found that curl can be tricked into copying
data beyond the end of its heap based buffer when asked to transfer an
RTSP URL. curl could calculate a wrong data length to copy from the
read buffer. This could lead to information leakage or a denial of
service.

For Debian 7 'Wheezy', these problems have been fixed in version
7.26.0-1+wheezy25.

We recommend that you upgrade your curl packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/03/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/curl"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-gnutls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-nss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-openssl-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/19");
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
if (deb_check(release:"7.0", prefix:"curl", reference:"7.26.0-1+wheezy25")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl3", reference:"7.26.0-1+wheezy25")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl3-dbg", reference:"7.26.0-1+wheezy25")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl3-gnutls", reference:"7.26.0-1+wheezy25")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl3-nss", reference:"7.26.0-1+wheezy25")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl4-gnutls-dev", reference:"7.26.0-1+wheezy25")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl4-nss-dev", reference:"7.26.0-1+wheezy25")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl4-openssl-dev", reference:"7.26.0-1+wheezy25")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
