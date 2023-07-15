#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3896. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101013);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7659", "CVE-2017-7668", "CVE-2017-7679");
  script_xref(name:"DSA", value:"3896");

  script_name(english:"Debian DSA-3896-1 : apache2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in the Apache HTTPD server.

  - CVE-2017-3167
    Emmanuel Dreyfus reported that the use of
    ap_get_basic_auth_pw() by third-party modules outside of
    the authentication phase may lead to authentication
    requirements being bypassed.

  - CVE-2017-3169
    Vasileios Panopoulos of AdNovum Informatik AG discovered
    that mod_ssl may dereference a NULL pointer when
    third-party modules call ap_hook_process_connection()
    during an HTTP request to an HTTPS port leading to a
    denial of service.

  - CVE-2017-7659
    Robert Swiecki reported that a specially crafted HTTP/2
    request could cause mod_http2 to dereference a NULL
    pointer and crash the server process.

  - CVE-2017-7668
    Javier Jimenez reported that the HTTP strict parsing
    contains a flaw leading to a buffer overread in
    ap_find_token(). A remote attacker can take advantage of
    this flaw by carefully crafting a sequence of request
    headers to cause a segmentation fault, or to force
    ap_find_token() to return an incorrect value.

  - CVE-2017-7679
    ChenQin and Hanno Boeck reported that mod_mime can read
    one byte past the end of a buffer when sending a
    malicious Content-Type response header."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-3167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-3169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-7659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-7668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-7679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-7659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/apache2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/apache2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3896"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apache2 packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 2.4.10-10+deb8u9. The oldstable distribution (jessie)
is not affected by CVE-2017-7659.

For the stable distribution (stretch), these problems have been fixed
in version 2.4.25-3+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/23");
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
if (deb_check(release:"8.0", prefix:"apache2", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-bin", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-data", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-dbg", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-dev", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-doc", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-event", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-itk", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-prefork", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-worker", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-suexec", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-suexec-custom", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-suexec-pristine", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-utils", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"apache2.2-bin", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"apache2.2-common", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-macro", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-proxy-html", reference:"2.4.10-10+deb8u9")) flag++;
if (deb_check(release:"9.0", prefix:"apache2", reference:"2.4.25-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-bin", reference:"2.4.25-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-data", reference:"2.4.25-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-dbg", reference:"2.4.25-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-dev", reference:"2.4.25-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-doc", reference:"2.4.25-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-ssl-dev", reference:"2.4.25-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-suexec-custom", reference:"2.4.25-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-suexec-pristine", reference:"2.4.25-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-utils", reference:"2.4.25-3+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
