#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4255. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111317);
  script_version("1.3");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_cve_id("CVE-2018-10886");
  script_xref(name:"DSA", value:"4255");

  script_name(english:"Debian DSA-4255-1 : ant - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Danny Grander reported that the unzip and untar tasks in ant, a Java
based build tool like make, allow the extraction of files outside a
target directory. An attacker can take advantage of this flaw by
submitting a specially crafted Zip or Tar archive to an ant build to
overwrite any file writable by the user running ant."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/ant"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/ant"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4255"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ant packages.

For the stable distribution (stretch), this problem has been fixed in
version 1.9.9-1+deb9u1."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ant");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/25");
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
if (deb_check(release:"9.0", prefix:"ant", reference:"1.9.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ant-doc", reference:"1.9.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ant-gcj", reference:"1.9.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ant-optional", reference:"1.9.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ant-optional-gcj", reference:"1.9.9-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
