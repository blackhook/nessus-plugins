#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4018. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104402);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-3735", "CVE-2017-3736");
  script_xref(name:"DSA", value:"4018");

  script_name(english:"Debian DSA-4018-1 : openssl - security update");
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

  - CVE-2017-3735
    It was discovered that OpenSSL is prone to a one-byte
    buffer overread while parsing a malformed
    IPAddressFamily extension in an X.509 certificate.

  Details can be found in the upstream advisory:
  https://www.openssl.org/news/secadv/20170828.txt

  - CVE-2017-3736
    It was discovered that OpenSSL contains a carry
    propagation bug in the x86_64 Montgomery squaring
    procedure.

  Details can be found in the upstream advisory:
  https://www.openssl.org/news/secadv/20171102.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-3735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20170828.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-3736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20171102.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-3735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-3736"
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
    value:"https://www.debian.org/security/2017/dsa-4018"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages.

For the oldstable distribution (jessie), CVE-2017-3735 has been fixed
in version 1.0.1t-1+deb8u7. The oldstable distribution is not affected
by CVE-2017-3736.

For the stable distribution (stretch), these problems have been fixed
in version 1.1.0f-3+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/06");
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
if (deb_check(release:"8.0", prefix:"libcrypto1.0.0-udeb", reference:"1.0.1t-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libssl-dev", reference:"1.0.1t-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libssl-doc", reference:"1.0.1t-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libssl1.0.0", reference:"1.0.1t-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libssl1.0.0-dbg", reference:"1.0.1t-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"openssl", reference:"1.0.1t-1+deb8u7")) flag++;
if (deb_check(release:"9.0", prefix:"libcrypto1.1-udeb", reference:"1.1.0f-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libssl-dev", reference:"1.1.0f-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libssl-doc", reference:"1.1.0f-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libssl1.1", reference:"1.1.0f-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libssl1.1-udeb", reference:"1.1.0f-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openssl", reference:"1.1.0f-3+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
