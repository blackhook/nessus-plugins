#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1747. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35979);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-4316");
  script_bugtraq_id(34100);
  script_xref(name:"DSA", value:"1747");

  script_name(english:"Debian DSA-1747-1 : glib2.0 - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Diego Petteno discovered that glib2.0, the GLib library of C
routines, handles large strings insecurely via its Base64 encoding
functions. This could possible lead to the execution of arbitrary
code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=520046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2009/dsa-1747"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the glib2.0 packages.

For the stable distribution (lenny), this problem has been fixed in
version 2.16.6-1+lenny1.

For the oldstable distribution (etch), this problem has been fixed in
version 2.12.4-2+etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glib2.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/22");
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
if (deb_check(release:"4.0", prefix:"libglib2.0-0", reference:"2.12.4-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libglib2.0-0-dbg", reference:"2.12.4-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libglib2.0-data", reference:"2.12.4-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libglib2.0-dev", reference:"2.12.4-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libglib2.0-doc", reference:"2.12.4-2+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"libgio-fam", reference:"2.16.6-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libglib2.0-0", reference:"2.16.6-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libglib2.0-0-dbg", reference:"2.16.6-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libglib2.0-data", reference:"2.16.6-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libglib2.0-dev", reference:"2.16.6-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libglib2.0-doc", reference:"2.16.6-1+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
