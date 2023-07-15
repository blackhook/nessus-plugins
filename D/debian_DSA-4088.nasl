#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4088. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106056);
  script_version("3.5");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2017-1000422");
  script_xref(name:"DSA", value:"4088");

  script_name(english:"Debian DSA-4088-1 : gdk-pixbuf - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that multiple integer overflows in the GIF image
loader in the GDK Pixbuf library may result in denial of service and
potentially the execution of arbitrary code if a malformed image file
is opened."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-6312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-6313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-6314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/gdk-pixbuf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/gdk-pixbuf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/gdk-pixbuf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4088"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gdk-pixbuf packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 2.31.1-2+deb8u7.

For the stable distribution (stretch), this problem has been fixed in
version 2.36.5-2+deb9u2. In addition this update provides fixes for
CVE-2017-6312, CVE-2017-6313 and CVE-2017-6314."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gdk-pixbuf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/16");
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
if (deb_check(release:"8.0", prefix:"gir1.2-gdkpixbuf-2.0", reference:"2.31.1-2+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libgdk-pixbuf2.0-0", reference:"2.31.1-2+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libgdk-pixbuf2.0-0-dbg", reference:"2.31.1-2+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libgdk-pixbuf2.0-common", reference:"2.31.1-2+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libgdk-pixbuf2.0-dev", reference:"2.31.1-2+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libgdk-pixbuf2.0-doc", reference:"2.31.1-2+deb8u7")) flag++;
if (deb_check(release:"9.0", prefix:"gir1.2-gdkpixbuf-2.0", reference:"2.36.5-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libgdk-pixbuf2.0-0", reference:"2.36.5-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libgdk-pixbuf2.0-0-udeb", reference:"2.36.5-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libgdk-pixbuf2.0-common", reference:"2.36.5-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libgdk-pixbuf2.0-dev", reference:"2.36.5-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libgdk-pixbuf2.0-doc", reference:"2.36.5-2+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
