#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1894. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(44759);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-2905");
  script_xref(name:"DSA", value:"1894");

  script_name(english:"Debian DSA-1894-1 : newt - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Miroslav Lichvar discovered that newt, a windowing toolkit, is prone
to a buffer overflow in the content processing code, which can lead to
the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2009/dsa-1894"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the newt packages.

For the oldstable distribution (etch), this problem has been fixed in
version 0.52.2-10+etch1.

For the stable distribution (lenny), this problem has been fixed in
version 0.52.2-11.3+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:newt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"4.0", prefix:"libnewt-dev", reference:"0.52.2-10+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnewt-pic", reference:"0.52.2-10+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnewt0.52", reference:"0.52.2-10+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"newt-tcl", reference:"0.52.2-10+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"python-newt", reference:"0.52.2-10+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"whiptail", reference:"0.52.2-10+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"libnewt-dev", reference:"0.52.2-11.3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libnewt-pic", reference:"0.52.2-11.3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libnewt0.52", reference:"0.52.2-11.3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"newt-tcl", reference:"0.52.2-11.3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python-newt", reference:"0.52.2-11.3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"whiptail", reference:"0.52.2-11.3+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
