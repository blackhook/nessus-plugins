#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-546. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15383);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2004-0753", "CVE-2004-0782", "CVE-2004-0783", "CVE-2004-0788");
  script_xref(name:"CERT", value:"577654");
  script_xref(name:"CERT", value:"729894");
  script_xref(name:"CERT", value:"825374");
  script_xref(name:"DSA", value:"546");

  script_name(english:"Debian DSA-546-1 : gdk-pixbuf - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Evans discovered several problems in gdk-pixbuf, the GdkPixBuf
library used in Gtk. It is possible for an attacker to execute
arbitrary code on the victims machine. Gdk-pixbuf for Gtk+1.2 is an
external package. For Gtk+2.0 it's part of the main gtk package.

The Common Vulnerabilities and Exposures Project identifies the
following vulnerabilities :

  - CAN-2004-0753
    Denial of service in bmp loader.

  - CAN-2004-0782

    Heap-based overflow in pixbuf_create_from_xpm.

  - CAN-2004-0788

    Integer overflow in the ico loader."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-546"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gdk-pixbuf packages.

For the stable distribution (woody) these problems have been fixed in
version 0.17.0-2woody2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gdk-pixbuf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libgdk-pixbuf-dev", reference:"0.17.0-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libgdk-pixbuf-gnome-dev", reference:"0.17.0-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libgdk-pixbuf-gnome2", reference:"0.17.0-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libgdk-pixbuf2", reference:"0.17.0-2woody2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
