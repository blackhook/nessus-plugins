#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3980. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103364);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-9798");
  script_xref(name:"DSA", value:"3980");

  script_name(english:"Debian DSA-3980-1 : apache2 - security update (Optionsbleed)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Hanno Boeck discovered that incorrect parsing of Limit directives of
.htaccess files by the Apache HTTP Server could result in memory
disclosure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=876109"
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
    value:"https://www.debian.org/security/2017/dsa-3980"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apache2 packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 2.4.10-10+deb8u11.

For the stable distribution (stretch), this problem has been fixed in
version 2.4.25-3+deb9u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/21");
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
if (deb_check(release:"8.0", prefix:"apache2", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-bin", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-data", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-dbg", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-dev", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-doc", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-event", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-itk", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-prefork", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-worker", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-suexec", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-suexec-custom", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-suexec-pristine", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-utils", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"apache2.2-bin", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"apache2.2-common", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-macro", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-proxy-html", reference:"2.4.10-10+deb8u11")) flag++;
if (deb_check(release:"9.0", prefix:"apache2", reference:"2.4.25-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-bin", reference:"2.4.25-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-data", reference:"2.4.25-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-dbg", reference:"2.4.25-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-dev", reference:"2.4.25-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-doc", reference:"2.4.25-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-ssl-dev", reference:"2.4.25-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-suexec-custom", reference:"2.4.25-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-suexec-pristine", reference:"2.4.25-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-utils", reference:"2.4.25-3+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
