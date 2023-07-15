#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3960. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102927);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-7526");
  script_xref(name:"DSA", value:"3960");

  script_name(english:"Debian DSA-3960-1 : gnupg - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Daniel J. Bernstein, Joachim Breitner, Daniel Genkin, Leon Groot
Bruinderink, Nadia Heninger, Tanja Lange, Christine van Vredendaal and
Yuval Yarom discovered that GnuPG is prone to a local side-channel
attack allowing full key recovery for RSA-1024.

See https://eprint.iacr.org/2017/627 for details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://eprint.iacr.org/2017/627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/gnupg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3960"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gnupg packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 1.4.18-7+deb8u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnupg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/05");
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
if (deb_check(release:"8.0", prefix:"gnupg", reference:"1.4.18-7+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gnupg-curl", reference:"1.4.18-7+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gnupg-udeb", reference:"1.4.18-7+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gpgv", reference:"1.4.18-7+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gpgv-udeb", reference:"1.4.18-7+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gpgv-win32", reference:"1.4.18-7+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
