#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4007. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104222);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-1000257");
  script_xref(name:"DSA", value:"4007");

  script_name(english:"Debian DSA-4007-1 : curl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Brian Carpenter, Geeknik Labs and 0xd34db347 discovered that cURL, an
URL transfer library, incorrectly parsed an IMAP FETCH response with
size 0, leading to an out-of-bounds read."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/curl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/curl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4007"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the curl packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 7.38.0-4+deb8u7.

For the stable distribution (stretch), this problem has been fixed in
version 7.52.1-5+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"curl", reference:"7.38.0-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3", reference:"7.38.0-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3-dbg", reference:"7.38.0-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3-gnutls", reference:"7.38.0-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3-nss", reference:"7.38.0-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-doc", reference:"7.38.0-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-gnutls-dev", reference:"7.38.0-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-nss-dev", reference:"7.38.0-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-openssl-dev", reference:"7.38.0-4+deb8u7")) flag++;
if (deb_check(release:"9.0", prefix:"curl", reference:"7.52.1-5+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl3", reference:"7.52.1-5+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl3-dbg", reference:"7.52.1-5+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl3-gnutls", reference:"7.52.1-5+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl3-nss", reference:"7.52.1-5+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl4-doc", reference:"7.52.1-5+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl4-gnutls-dev", reference:"7.52.1-5+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl4-nss-dev", reference:"7.52.1-5+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl4-openssl-dev", reference:"7.52.1-5+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
