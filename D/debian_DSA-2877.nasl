#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2877. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72992);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-2323", "CVE-2014-2324");
  script_bugtraq_id(66153, 66157);
  script_xref(name:"DSA", value:"2877");

  script_name(english:"Debian DSA-2877-1 : lighttpd - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the lighttpd web server.

  - CVE-2014-2323
    Jann Horn discovered that specially crafted host names
    can be used to inject arbitrary MySQL queries in
    lighttpd servers using the MySQL virtual hosting module
    (mod_mysql_vhost).

  This only affects installations with the lighttpd-mod-mysql-vhost
  binary package installed and in use.

  - CVE-2014-2324
    Jann Horn discovered that specially crafted host names
    can be used to traverse outside of the document root
    under certain situations in lighttpd servers using
    either the mod_mysql_vhost, mod_evhost, or
    mod_simple_vhost virtual hosting modules.

  Servers not using these modules are not affected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=741493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-2323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-2324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/lighttpd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/lighttpd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2014/dsa-2877"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lighttpd packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1.4.28-2+squeeze1.6.

For the stable distribution (wheezy), these problems have been fixed
in version 1.4.31-4+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"lighttpd", reference:"1.4.28-2+squeeze1.6")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-doc", reference:"1.4.28-2+squeeze1.6")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-cml", reference:"1.4.28-2+squeeze1.6")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-magnet", reference:"1.4.28-2+squeeze1.6")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-mysql-vhost", reference:"1.4.28-2+squeeze1.6")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-trigger-b4-dl", reference:"1.4.28-2+squeeze1.6")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-webdav", reference:"1.4.28-2+squeeze1.6")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd", reference:"1.4.31-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-doc", reference:"1.4.31-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-mod-cml", reference:"1.4.31-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-mod-magnet", reference:"1.4.31-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-mod-mysql-vhost", reference:"1.4.31-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-mod-trigger-b4-dl", reference:"1.4.31-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-mod-webdav", reference:"1.4.31-4+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
