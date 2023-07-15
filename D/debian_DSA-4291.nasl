#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4291. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117436);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_cve_id("CVE-2018-16741");
  script_xref(name:"DSA", value:"4291");

  script_name(english:"Debian DSA-4291-1 : mgetty - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two input sanitization failures have been found in the faxrunq and
faxq binaries in mgetty, a smart modem getty replacement. An attacker
could leverage them to insert commands via shell metacharacters in
jobs id and have them executed with the privilege of the faxrunq/faxq
user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/mgetty"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/mgetty"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4291"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mgetty packages.

For the stable distribution (stretch), this problem has been fixed in
version 1.1.36-3+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mgetty");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/12");
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
if (deb_check(release:"9.0", prefix:"mgetty", reference:"1.1.36-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mgetty-docs", reference:"1.1.36-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mgetty-fax", reference:"1.1.36-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mgetty-pvftools", reference:"1.1.36-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mgetty-viewfax", reference:"1.1.36-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mgetty-voice", reference:"1.1.36-3+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
