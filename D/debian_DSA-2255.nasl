#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2255. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55043);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_bugtraq_id(48056);
  script_xref(name:"DSA", value:"2255");

  script_name(english:"Debian DSA-2255-1 : libxml2 - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Evans discovered that libxml was vulnerable to buffer overflows,
which allowed a crafted XML input file to potentially execute
arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=628537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libxml2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2011/dsa-2255"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxml2 packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.6.32.dfsg-5+lenny4.

For the stable distribution (squeeze), this problem has been fixed in
version 2.7.8.dfsg-2+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"5.0", prefix:"libxml2", reference:"2.6.32.dfsg-5+lenny4")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2", reference:"2.7.8.dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2-dbg", reference:"2.7.8.dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2-dev", reference:"2.7.8.dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2-doc", reference:"2.7.8.dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2-utils", reference:"2.7.8.dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"python-libxml2", reference:"2.7.8.dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"python-libxml2-dbg", reference:"2.7.8.dfsg-2+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
