#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3986. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103578);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-11714", "CVE-2017-9611", "CVE-2017-9612", "CVE-2017-9726", "CVE-2017-9727", "CVE-2017-9739", "CVE-2017-9835");
  script_xref(name:"DSA", value:"3986");

  script_name(english:"Debian DSA-3986-1 : ghostscript - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Ghostscript, the GPL
PostScript/PDF interpreter, which may result in denial of service if a
specially crafted Postscript file is processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=869907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=869910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=869913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=869915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=869916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=869917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=869977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ghostscript"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/ghostscript"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3986"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ghostscript packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 9.06~dfsg-2+deb8u6.

For the stable distribution (stretch), these problems have been fixed
in version 9.20~dfsg-3.2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"ghostscript", reference:"9.06~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"ghostscript-dbg", reference:"9.06~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"ghostscript-doc", reference:"9.06~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"ghostscript-x", reference:"9.06~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libgs-dev", reference:"9.06~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libgs9", reference:"9.06~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libgs9-common", reference:"9.06~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"9.0", prefix:"ghostscript", reference:"9.20~dfsg-3.2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ghostscript-dbg", reference:"9.20~dfsg-3.2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ghostscript-doc", reference:"9.20~dfsg-3.2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ghostscript-x", reference:"9.20~dfsg-3.2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgs-dev", reference:"9.20~dfsg-3.2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgs9", reference:"9.20~dfsg-3.2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgs9-common", reference:"9.20~dfsg-3.2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
