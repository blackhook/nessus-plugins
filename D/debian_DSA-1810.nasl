#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1810. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38991);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-5519");
  script_bugtraq_id(35169);
  script_xref(name:"DSA", value:"1810");

  script_name(english:"Debian DSA-1810-1 : libapache-mod-jk - information disclosure");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An information disclosure flaw was found in mod_jk, the Tomcat
Connector module for Apache. If a buggy client included the
'Content-Length' header without providing request body data, or if a
client sent repeated requests very quickly, one client could obtain a
response intended for another client.

The oldstable distribution (etch), this problem has been fixed in
version 1:1.2.18-3etch2."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=523054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2009/dsa-1810"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libapache-mod-jk packages.

For the stable distribution (lenny), this problem has been fixed in
version 1:1.2.26-2+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache-mod-jk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"4.0", prefix:"libapache-mod-jk", reference:"1.2.18-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libapache-mod-jk-doc", reference:"1.2.18-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libapache2-mod-jk", reference:"1.2.18-3etch2")) flag++;
if (deb_check(release:"5.0", prefix:"libapache-mod-jk-doc", reference:"1:1.2.26-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libapache2-mod-jk", reference:"1:1.2.26-2+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
