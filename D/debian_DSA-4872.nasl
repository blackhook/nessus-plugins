#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4872. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(147904);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/19");
  script_xref(name:"DSA", value:"4872");

  script_name(english:"Debian DSA-4872-1 : shibboleth-sp - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Toni Huttunen discovered that the Shibboleth service provider's
template engine used to render error pages could be abused for
phishing attacks.

For additional information please refer to the upstream advisory at
https://shibboleth.net/community/advisories/secadv_20210317.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=985405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://shibboleth.net/community/advisories/secadv_20210317.txt"
  );
  # https://security-tracker.debian.org/tracker/source-package/shibboleth-sp
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82c1ec06"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/shibboleth-sp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4872"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the shibboleth-sp packages.

For the stable distribution (buster), this problem has been fixed in
version 3.0.4+dfsg1-1+deb10u1."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:shibboleth-sp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"libapache2-mod-shib", reference:"3.0.4+dfsg1-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libapache2-mod-shib2", reference:"3.0.4+dfsg1-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libshibsp-dev", reference:"3.0.4+dfsg1-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libshibsp-doc", reference:"3.0.4+dfsg1-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libshibsp-plugins", reference:"3.0.4+dfsg1-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libshibsp8", reference:"3.0.4+dfsg1-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"shibboleth-sp-common", reference:"3.0.4+dfsg1-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"shibboleth-sp-utils", reference:"3.0.4+dfsg1-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"shibboleth-sp2-common", reference:"3.0.4+dfsg1-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"shibboleth-sp2-utils", reference:"3.0.4+dfsg1-1+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
