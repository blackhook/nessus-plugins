#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2958. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74499);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-0478");
  script_xref(name:"DSA", value:"2958");

  script_name(english:"Debian DSA-2958-1 : apt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jakub Wilk discovered that APT, the high level package manager, did
not properly perform authentication checks for source packages
downloaded via 'apt-get source'. This only affects use cases where
source packages are downloaded via this command; it does not affect
regular Debian package installation and upgrading."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=749795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/apt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2014/dsa-2958"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apt packages.

For the stable distribution (wheezy), this problem has been fixed in
version 0.9.7.9+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"apt", reference:"0.9.7.9+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"apt-doc", reference:"0.9.7.9+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"apt-transport-https", reference:"0.9.7.9+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"apt-utils", reference:"0.9.7.9+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libapt-inst1.5", reference:"0.9.7.9+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libapt-pkg-dev", reference:"0.9.7.9+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libapt-pkg-doc", reference:"0.9.7.9+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libapt-pkg4.12", reference:"0.9.7.9+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
