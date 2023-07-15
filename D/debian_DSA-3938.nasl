#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3938. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102445);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-7890");
  script_xref(name:"DSA", value:"3938");

  script_name(english:"Debian DSA-3938-1 : libgd2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Matviy Kotoniy reported that the gdImageCreateFromGifCtx() function
used to load images from GIF format files in libgd2, a library for
programmatic graphics creation and manipulation, does not zero stack
allocated color map buffers before their use, which may result in
information disclosure if a specially crafted file is processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=869263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libgd2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libgd2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3938"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libgd2 packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 2.1.0-5+deb8u10.

For the stable distribution (stretch), this problem has been fixed in
version 2.2.4-2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgd2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/14");
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
if (deb_check(release:"8.0", prefix:"libgd-dbg", reference:"2.1.0-5+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"libgd-dev", reference:"2.1.0-5+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"libgd-tools", reference:"2.1.0-5+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"libgd2-noxpm-dev", reference:"2.1.0-5+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"libgd2-xpm-dev", reference:"2.1.0-5+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"libgd3", reference:"2.1.0-5+deb8u10")) flag++;
if (deb_check(release:"9.0", prefix:"libgd-dev", reference:"2.2.4-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgd-tools", reference:"2.2.4-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgd3", reference:"2.2.4-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
