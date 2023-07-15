#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4241. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110929);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_cve_id("CVE-2018-12910");
  script_xref(name:"DSA", value:"4241");

  script_name(english:"Debian DSA-4241-1 : libsoup2.4 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Soup HTTP library performed insufficient
validation of cookie requests which could result in an out-of-bounds
memory read."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/libsoup2.4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libsoup2.4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4241"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libsoup2.4 packages.

For the stable distribution (stretch), this problem has been fixed in
version 2.56.0-2+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsoup2.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/06");
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
if (deb_check(release:"9.0", prefix:"gir1.2-soup-2.4", reference:"2.56.0-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libsoup-gnome2.4-1", reference:"2.56.0-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libsoup-gnome2.4-dev", reference:"2.56.0-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libsoup2.4-1", reference:"2.56.0-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libsoup2.4-dev", reference:"2.56.0-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libsoup2.4-doc", reference:"2.56.0-2+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
