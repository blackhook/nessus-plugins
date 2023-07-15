#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3889. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100880);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-1000376");
  script_xref(name:"DSA", value:"3889");

  script_name(english:"Debian DSA-3889-1 : libffi - security update (Stack Clash)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libffi, a library used to call code written in one language from code
written in a different language, was enforcing an executable stack on
the i386 architecture. While this might not be considered a
vulnerability by itself, this could be leveraged when exploiting other
vulnerabilities, like for example the 'stack clash' class of
vulnerabilities discovered by Qualys Research Labs. For the full
details, please refer to their advisory published at:
https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=751907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libffi"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libffi"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3889"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libffi packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 3.1-2+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 3.2.1-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libffi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/20");
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
if (deb_check(release:"8.0", prefix:"libffi-dev", reference:"3.1-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libffi6", reference:"3.1-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libffi6-dbg", reference:"3.1-2+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"libffi-dev", reference:"3.2.1-4")) flag++;
if (deb_check(release:"9.0", prefix:"libffi6", reference:"3.2.1-4")) flag++;
if (deb_check(release:"9.0", prefix:"libffi6-dbg", reference:"3.2.1-4")) flag++;
if (deb_check(release:"9.0", prefix:"libffi6-udeb", reference:"3.2.1-4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
