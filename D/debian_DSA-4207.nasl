#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4207. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109968);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_cve_id("CVE-2018-1106");
  script_xref(name:"DSA", value:"4207");

  script_name(english:"Debian DSA-4207-1 : packagekit - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Matthias Gerstner discovered that PackageKit, a DBus abstraction layer
for simple software management tasks, contains an authentication
bypass flaw allowing users without privileges to install local
packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=896703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/packagekit"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/packagekit"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4207"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the packagekit packages.

For the stable distribution (stretch), this problem has been fixed in
version 1.1.5-2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:packagekit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/23");
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
if (deb_check(release:"9.0", prefix:"gir1.2-packagekitglib-1.0", reference:"1.1.5-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gstreamer1.0-packagekit", reference:"1.1.5-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpackagekit-glib2-18", reference:"1.1.5-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpackagekit-glib2-dev", reference:"1.1.5-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"packagekit", reference:"1.1.5-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"packagekit-command-not-found", reference:"1.1.5-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"packagekit-docs", reference:"1.1.5-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"packagekit-gtk3-module", reference:"1.1.5-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"packagekit-tools", reference:"1.1.5-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
