#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3337. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85517);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-4491");
  script_xref(name:"DSA", value:"3337");

  script_name(english:"Debian DSA-3337-1 : gdk-pixbuf - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Gustavo Grieco discovered a heap overflow in the processing of BMP
images which may result in the execution of arbitrary code if a
malformed image is opened."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/gdk-pixbuf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/gdk-pixbuf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2015/dsa-3337"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gdk-pixbuf packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 2.26.1-1+deb7u3.

For the stable distribution (jessie), this problem has been fixed in
version 2.31.1-2+deb8u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gdk-pixbuf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"gir1.2-gdkpixbuf-2.0", reference:"2.26.1-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libgdk-pixbuf2.0-0", reference:"2.26.1-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libgdk-pixbuf2.0-common", reference:"2.26.1-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libgdk-pixbuf2.0-dev", reference:"2.26.1-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libgdk-pixbuf2.0-doc", reference:"2.26.1-1+deb7u3")) flag++;
if (deb_check(release:"8.0", prefix:"gir1.2-gdkpixbuf-2.0", reference:"2.31.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libgdk-pixbuf2.0-0", reference:"2.31.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libgdk-pixbuf2.0-0-dbg", reference:"2.31.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libgdk-pixbuf2.0-common", reference:"2.31.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libgdk-pixbuf2.0-dev", reference:"2.31.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libgdk-pixbuf2.0-doc", reference:"2.31.1-2+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
