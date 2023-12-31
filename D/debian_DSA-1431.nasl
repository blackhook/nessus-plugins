#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1431. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29339);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-6183");
  script_xref(name:"DSA", value:"1431");

  script_name(english:"Debian DSA-1431-1 : ruby-gnome2 - format string");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that ruby-gnome2, the GNOME-related bindings for the
Ruby language, didn't properly sanitize input prior to constructing
dialogs. This could allow the execution of arbitrary code if untrusted
input is displayed within a dialog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=453689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2007/dsa-1431"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ruby-gnome2 package.

For the old stable distribution (sarge), this problem has been fixed
in version 0.12.0-2sarge1.

For the stable distribution (etch), this problem has been fixed in
version 0.15.0-1.1etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/12");
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
if (deb_check(release:"3.1", prefix:"libart2-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libatk1-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgconf2-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgda2-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgdk-pixbuf2-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libglade2-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libglib2-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgnome2-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgnomecanvas2-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgnomeprint2-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgnomeprintui2-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgnomevfs2-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgstreamer0.8-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgtk2-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgtkglext1-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgtkhtml2-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgtksourceview1-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libpanel-applet2-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libpango1-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"librsvg2-ruby", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ruby-gnome2", reference:"0.12.0-2sarge1")) flag++;
if (deb_check(release:"4.0", prefix:"libart2-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libatk1-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgconf2-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgda2-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgdk-pixbuf2-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libglade2-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libglib2-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgnome2-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgnomecanvas2-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgnomeprint2-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgnomeprintui2-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgnomevfs2-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgstreamer0.8-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgtk-mozembed-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgtk2-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgtkglext1-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgtkhtml2-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgtksourceview1-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpanel-applet2-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpango1-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"librsvg2-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libvte-ruby", reference:"0.15.0-1.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ruby-gnome2", reference:"0.15.0-1.1etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
