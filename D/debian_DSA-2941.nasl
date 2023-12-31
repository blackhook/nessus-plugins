#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2941. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74277);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-3146");
  script_bugtraq_id(67159);
  script_xref(name:"DSA", value:"2941");

  script_name(english:"Debian DSA-2941-1 : lxml - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that clean_html() function of lxml (pythonic
bindings for the libxml2 and libxslt libraries) performed insufficient
sanitisation for some non-printable characters. This could lead to
cross-site scripting."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/lxml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2014/dsa-2941"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lxml packages.

For the stable distribution (wheezy), this problem has been fixed in
version 2.3.2-1+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lxml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/03");
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
if (deb_check(release:"7.0", prefix:"python-lxml", reference:"2.3.2-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python-lxml-dbg", reference:"2.3.2-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python-lxml-doc", reference:"2.3.2-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python3-lxml", reference:"2.3.2-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python3-lxml-dbg", reference:"2.3.2-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
