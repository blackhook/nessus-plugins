#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4059. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105120);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-16612");
  script_xref(name:"DSA", value:"4059");

  script_name(english:"Debian DSA-4059-1 : libxcursor - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that libXcursor, a X cursor management library, is
prone to several heap overflows when parsing malicious files. An
attacker can take advantage of these flaws for arbitrary code
execution, if a user is tricked into processing a specially crafted
cursor file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=883792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/libxcursor"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libxcursor"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libxcursor"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4059"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxcursor packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 1:1.1.14-1+deb8u1.

For the stable distribution (stretch), these problems have been fixed
in version 1:1.1.14-1+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxcursor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/11");
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
if (deb_check(release:"8.0", prefix:"libxcursor-dev", reference:"1:1.1.14-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libxcursor1", reference:"1:1.1.14-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libxcursor1-dbg", reference:"1:1.1.14-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libxcursor1-udeb", reference:"1:1.1.14-1+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxcursor-dev", reference:"1:1.1.14-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxcursor1", reference:"1:1.1.14-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxcursor1-dbg", reference:"1:1.1.14-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxcursor1-udeb", reference:"1:1.1.14-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
