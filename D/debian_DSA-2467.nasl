#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2467. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59061);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-2351");
  script_xref(name:"DSA", value:"2467");

  script_name(english:"Debian DSA-2467-1 : mahara - insecure defaults");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Mahara, the portfolio, weblog, and resume
builder, had an insecure default with regards to SAML-based
authentication used with more than one SAML identity provider. Someone
with control over one IdP could impersonate users from other IdP's."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/mahara"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2012/dsa-2467"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mahara packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1.2.6-2+squeeze4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mahara");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"mahara", reference:"1.2.6-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"mahara-apache2", reference:"1.2.6-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"mahara-mediaplayer", reference:"1.2.6-2+squeeze4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
