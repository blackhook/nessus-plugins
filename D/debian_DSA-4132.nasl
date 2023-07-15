#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4132. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107124);
  script_version("3.3");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2017-13194");
  script_xref(name:"DSA", value:"4132");

  script_name(english:"Debian DSA-4132-1 : libvpx - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that incorrect validation of frame widths in the
libvpx multimedia library may result in denial of service and
potentially the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/libvpx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libvpx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libvpx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4132"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libvpx packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 1.3.0-3+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 1.6.1-3+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvpx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/05");
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
if (deb_check(release:"8.0", prefix:"libvpx-dev", reference:"1.3.0-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libvpx-doc", reference:"1.3.0-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libvpx1", reference:"1.3.0-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libvpx1-dbg", reference:"1.3.0-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vpx-tools", reference:"1.3.0-3+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvpx-dev", reference:"1.6.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvpx-doc", reference:"1.6.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvpx4", reference:"1.6.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vpx-tools", reference:"1.6.1-3+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
