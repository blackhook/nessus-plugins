#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1326. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25638);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-2837");
  script_xref(name:"DSA", value:"1326");

  script_name(english:"Debian DSA-1326-1 : fireflier-server - insecure temporary files");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Steve Kemp from the Debian Security Audit project discovered that
fireflier-server, an interactive firewall rule creation tool, uses
temporary files in an unsafe manner which may be exploited to remove
arbitrary files from the local system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2007/dsa-1326"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the fireflier-server package.

For the old stable distribution (sarge) this problem has been fixed in
version 1.1.5-1sarge1.

For the stable distribution (etch) this problem has been fixed in
version 1.1.6-3etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fireflier-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"3.1", prefix:"fireflier-server", reference:"1.1.5-1sarge1")) flag++;
if (deb_check(release:"4.0", prefix:"fireflier-client-gtk", reference:"1.1.6-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"fireflier-client-kde", reference:"1.1.6-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"fireflier-client-qt", reference:"1.1.6-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"fireflier-server", reference:"1.1.6-3etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
