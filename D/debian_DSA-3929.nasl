#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3929. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102370);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-2885");
  script_xref(name:"DSA", value:"3929");

  script_name(english:"Debian DSA-3929-1 : libsoup2.4 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Aleksandar Nikolic of Cisco Talos discovered a stack-based buffer
overflow vulnerability in libsoup2.4, a HTTP library implementation in
C. A remote attacker can take advantage of this flaw by sending a
specially crafted HTTP request to cause an application using the
libsoup2.4 library to crash (denial of service), or potentially
execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=871650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libsoup2.4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libsoup2.4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3929"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libsoup2.4 packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 2.48.0-1+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 2.56.0-2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsoup2.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/11");
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
if (deb_check(release:"8.0", prefix:"gir1.2-soup-2.4", reference:"2.48.0-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsoup-gnome2.4-1", reference:"2.48.0-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsoup-gnome2.4-dev", reference:"2.48.0-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsoup2.4-1", reference:"2.48.0-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsoup2.4-dbg", reference:"2.48.0-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsoup2.4-dev", reference:"2.48.0-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsoup2.4-doc", reference:"2.48.0-1+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"gir1.2-soup-2.4", reference:"2.56.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsoup-gnome2.4-1", reference:"2.56.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsoup-gnome2.4-dev", reference:"2.56.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsoup2.4-1", reference:"2.56.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsoup2.4-dev", reference:"2.56.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsoup2.4-doc", reference:"2.56.0-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
