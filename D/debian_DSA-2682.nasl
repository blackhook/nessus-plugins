#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2682. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66566);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-1982");
  script_xref(name:"DSA", value:"2682");

  script_name(english:"Debian DSA-2682-1 : libxext - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ilja van Sprundel of IOActive discovered several security issues in
multiple components of the X.org graphics stack and the related
libraries: Various integer overflows, sign handling errors in integer
conversions, buffer overflows, memory corruption and missing input
sanitising may lead to privilege escalation or denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libxext"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libxext"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2013/dsa-2682"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxext packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 2:1.1.2-1+squeeze1.

For the stable distribution (wheezy), this problem has been fixed in
version 2:1.3.1-2+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxext");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"libxext-dev", reference:"2:1.1.2-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxext6", reference:"2:1.1.2-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxext6-dbg", reference:"2:1.1.2-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxext6-udeb", reference:"2:1.1.2-1+squeeze1")) flag++;
if (deb_check(release:"7.0", prefix:"libxext-dev", reference:"2:1.3.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxext-doc", reference:"2:1.3.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxext6", reference:"2:1.3.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxext6-dbg", reference:"2:1.3.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxext6-udeb", reference:"2:1.3.1-2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
