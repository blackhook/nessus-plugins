#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4157. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108730);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2017-3738", "CVE-2018-0739");
  script_xref(name:"DSA", value:"4157");

  script_name(english:"Debian DSA-4157-1 : openssl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in OpenSSL, a Secure
Sockets Layer toolkit. The Common Vulnerabilities and Exposures
project identifies the following issues :

  - CVE-2017-3738
    David Benjamin of Google reported an overflow bug in the
    AVX2 Montgomery multiplication procedure used in
    exponentiation with 1024-bit moduli.

  - CVE-2018-0739
    It was discovered that constructed ASN.1 types with a
    recursive definition could exceed the stack, potentially
    leading to a denial of service.

Details can be found in the upstream advisory:
https://www.openssl.org/news/secadv/20180327.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-3738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-0739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20180327.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-3738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/openssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/openssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4157"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 1.0.1t-1+deb8u8. The oldstable distribution is not
affected by CVE-2017-3738.

For the stable distribution (stretch), these problems have been fixed
in version 1.1.0f-3+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libcrypto1.0.0-udeb", reference:"1.0.1t-1+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libssl-dev", reference:"1.0.1t-1+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libssl-doc", reference:"1.0.1t-1+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libssl1.0.0", reference:"1.0.1t-1+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libssl1.0.0-dbg", reference:"1.0.1t-1+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"openssl", reference:"1.0.1t-1+deb8u8")) flag++;
if (deb_check(release:"9.0", prefix:"libcrypto1.1-udeb", reference:"1.1.0f-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libssl-dev", reference:"1.1.0f-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libssl-doc", reference:"1.1.0f-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libssl1.1", reference:"1.1.0f-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libssl1.1-udeb", reference:"1.1.0f-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"openssl", reference:"1.1.0f-3+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
