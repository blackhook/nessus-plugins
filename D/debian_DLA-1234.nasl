#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1234-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105661);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-1234-2 : gdk-pixbuf regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The patch introduced in DLA-1234-1 had a problem that caused
gdk-pixbuf's gif module to fail to load.

For Debian 7 'Wheezy', these problems have been fixed in version
2.26.1-1+deb7u8.

We recommend that you upgrade your gdk-pixbuf packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/01/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/gdk-pixbuf"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-gdkpixbuf-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdk-pixbuf2.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdk-pixbuf2.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdk-pixbuf2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdk-pixbuf2.0-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"gir1.2-gdkpixbuf-2.0", reference:"2.26.1-1+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libgdk-pixbuf2.0-0", reference:"2.26.1-1+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libgdk-pixbuf2.0-common", reference:"2.26.1-1+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libgdk-pixbuf2.0-dev", reference:"2.26.1-1+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libgdk-pixbuf2.0-doc", reference:"2.26.1-1+deb7u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
