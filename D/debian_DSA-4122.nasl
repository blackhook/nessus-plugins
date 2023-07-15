#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4122. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106957);
  script_version("3.5");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2018-1000024", "CVE-2018-1000027");
  script_xref(name:"DSA", value:"4122");

  script_name(english:"Debian DSA-4122-1 : squid3 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Squid3, a fully
featured web proxy cache. The Common Vulnerabilities and Exposures
project identifies the following issues :

  - CVE-2018-1000024
    Louis Dion-Marcil discovered that Squid does not
    properly handle processing of certain ESI responses. A
    remote server delivering certain ESI response syntax can
    take advantage of this flaw to cause a denial of service
    for all clients accessing the Squid service. This
    problem is limited to the Squid custom ESI parser.

  - CVE-2018-1000027
    Louis Dion-Marcil discovered that Squid is prone to a
    denial of service vulnerability when processing ESI
    responses or downloading intermediate CA certificates. A
    remote attacker can take advantage of this flaw to cause
    a denial of service for all clients accessing the Squid
    service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=888719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=888720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1000024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1000027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/squid3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/squid3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/squid3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4122"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the squid3 packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 3.4.8-6+deb8u5.

For the stable distribution (stretch), these problems have been fixed
in version 3.5.23-5+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/23");
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
if (deb_check(release:"8.0", prefix:"squid-cgi", reference:"3.4.8-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"squid-purge", reference:"3.4.8-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"squid3", reference:"3.4.8-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"squid3-common", reference:"3.4.8-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"squid3-dbg", reference:"3.4.8-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"squidclient", reference:"3.4.8-6+deb8u5")) flag++;
if (deb_check(release:"9.0", prefix:"squid", reference:"3.5.23-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"squid-cgi", reference:"3.5.23-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"squid-common", reference:"3.5.23-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"squid-dbg", reference:"3.5.23-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"squid-purge", reference:"3.5.23-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"squid3", reference:"3.5.23-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"squidclient", reference:"3.5.23-5+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
