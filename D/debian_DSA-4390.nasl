#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4390. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122163);
  script_version("1.1");
  script_cvs_date("Date: 2019/02/14 10:37:32");

  script_xref(name:"DSA", value:"4390");

  script_name(english:"Debian DSA-4390-1 : flatpak - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Flatpak, an application deployment framework
for desktop apps, insufficiently restricted the execution of
'apply_extra'scripts which could potentially result in privilege
escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=922059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/flatpak"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/flatpak"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4390"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the flatpak packages.

For the stable distribution (stretch), this problem has been fixed in
version 0.8.9-0+deb9u2."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:flatpak");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"flatpak", reference:"0.8.9-0+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"flatpak-builder", reference:"0.8.9-0+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"flatpak-tests", reference:"0.8.9-0+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"gir1.2-flatpak-1.0", reference:"0.8.9-0+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libflatpak-dev", reference:"0.8.9-0+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libflatpak-doc", reference:"0.8.9-0+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libflatpak0", reference:"0.8.9-0+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
