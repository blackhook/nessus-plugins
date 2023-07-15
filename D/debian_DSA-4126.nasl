#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4126. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107026);
  script_version("3.6");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2018-0489");
  script_xref(name:"DSA", value:"4126");
  script_xref(name:"IAVB", value:"2018-B-0038");

  script_name(english:"Debian DSA-4126-1 : xmltooling - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Kelby Ludwig and Scott Cantor discovered that the Shibboleth service
provider is vulnerable to impersonation attacks and information
disclosure due to incorrect XML parsing. For additional details please
refer to the upstream advisory at
https://shibboleth.net/community/advisories/secadv_20180227.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://shibboleth.net/community/advisories/secadv_20180227.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/xmltooling"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/xmltooling"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/xmltooling"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4126"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xmltooling packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 1.5.3-2+deb8u3.

For the stable distribution (stretch), this problem has been fixed in
version 1.6.0-4+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xmltooling");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"8.0", prefix:"libxmltooling-dev", reference:"1.5.3-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libxmltooling-doc", reference:"1.5.3-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libxmltooling6", reference:"1.5.3-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"xmltooling-schemas", reference:"1.5.3-2+deb8u3")) flag++;
if (deb_check(release:"9.0", prefix:"libxmltooling-dev", reference:"1.6.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxmltooling-doc", reference:"1.6.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxmltooling7", reference:"1.6.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"xmltooling-schemas", reference:"1.6.0-4+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
