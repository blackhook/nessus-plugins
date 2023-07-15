#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4098. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106412);
  script_version("3.5");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2018-1000005", "CVE-2018-1000007");
  script_xref(name:"DSA", value:"4098");

  script_name(english:"Debian DSA-4098-1 : curl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in cURL, an URL transfer library.

  - CVE-2018-1000005
    Zhouyihai Ding discovered an out-of-bounds read in the
    code handling HTTP/2 trailers. This issue doesn't affect
    the oldstable distribution (jessie).

  - CVE-2018-1000007
    Craig de Stigter discovered that authentication data
    might be leaked to third parties when following HTTP
    redirects."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1000005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1000007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/curl"
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
    value:"https://www.debian.org/security/2018/dsa-4098"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the curl packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 7.38.0-4+deb8u9.

For the stable distribution (stretch), these problems have been fixed
in version 7.52.1-5+deb9u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/29");
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
if (deb_check(release:"8.0", prefix:"curl", reference:"7.38.0-4+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3", reference:"7.38.0-4+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3-dbg", reference:"7.38.0-4+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3-gnutls", reference:"7.38.0-4+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3-nss", reference:"7.38.0-4+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-doc", reference:"7.38.0-4+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-gnutls-dev", reference:"7.38.0-4+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-nss-dev", reference:"7.38.0-4+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-openssl-dev", reference:"7.38.0-4+deb8u9")) flag++;
if (deb_check(release:"9.0", prefix:"curl", reference:"7.52.1-5+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl3", reference:"7.52.1-5+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl3-dbg", reference:"7.52.1-5+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl3-gnutls", reference:"7.52.1-5+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl3-nss", reference:"7.52.1-5+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl4-doc", reference:"7.52.1-5+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl4-gnutls-dev", reference:"7.52.1-5+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl4-nss-dev", reference:"7.52.1-5+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl4-openssl-dev", reference:"7.52.1-5+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
