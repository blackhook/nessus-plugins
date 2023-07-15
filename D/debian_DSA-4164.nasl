#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4164. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108816);
  script_version("1.11");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2017-15710", "CVE-2017-15715", "CVE-2018-1283", "CVE-2018-1301", "CVE-2018-1303", "CVE-2018-1312");
  script_xref(name:"DSA", value:"4164");

  script_name(english:"Debian DSA-4164-1 : apache2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in the Apache HTTPD server.

  - CVE-2017-15710
    Alex Nichols and Jakob Hirsch reported that
    mod_authnz_ldap, if configured with
    AuthLDAPCharsetConfig, could cause an out of bound write
    if supplied with a crafted Accept-Language header. This
    could potentially be used for a Denial of Service
    attack.

  - CVE-2017-15715
    Elar Lang discovered that expression specified in
    <FilesMatch> could match '$' to a newline character in a
    malicious filename, rather than matching only the end of
    the filename. This could be exploited in environments
    where uploads of some files are externally blocked, but
    only by matching the trailing portion of the filename.

  - CVE-2018-1283
    When mod_session is configured to forward its session
    data to CGI applications (SessionEnv on, not the
    default), a remote user could influence their content by
    using a 'Session' header.

  - CVE-2018-1301
    Robert Swiecki reported that a specially crafted request
    could have crashed the Apache HTTP Server, due to an out
    of bound access after a size limit is reached by reading
    the HTTP header.

  - CVE-2018-1303
    Robert Swiecki reported that a specially crafted HTTP
    request header could have crashed the Apache HTTP Server
    if using mod_cache_socache, due to an out of bound read
    while preparing data to be cached in shared memory.

  - CVE-2018-1312
    Nicolas Daniels discovered that when generating an HTTP
    Digest authentication challenge, the nonce sent by
    mod_auth_digest to prevent replay attacks was not
    correctly generated using a pseudo-random seed. In a
    cluster of servers using a common Digest authentication
    configuration, HTTP requests could be replayed across
    servers by an attacker without detection."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/apache2"
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
    value:"https://www.debian.org/security/2018/dsa-4164"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apache2 packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 2.4.10-10+deb8u12.

For the stable distribution (stretch), these problems have been fixed
in version 2.4.25-3+deb9u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/04");
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
if (deb_check(release:"8.0", prefix:"apache2", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-bin", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-data", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-dbg", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-dev", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-doc", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-event", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-itk", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-prefork", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-worker", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-suexec", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-suexec-custom", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-suexec-pristine", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-utils", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"apache2.2-bin", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"apache2.2-common", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-macro", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-proxy-html", reference:"2.4.10-10+deb8u12")) flag++;
if (deb_check(release:"9.0", prefix:"apache2", reference:"2.4.25-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-bin", reference:"2.4.25-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-data", reference:"2.4.25-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-dbg", reference:"2.4.25-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-dev", reference:"2.4.25-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-doc", reference:"2.4.25-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-ssl-dev", reference:"2.4.25-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-suexec-custom", reference:"2.4.25-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-suexec-pristine", reference:"2.4.25-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-utils", reference:"2.4.25-3+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
