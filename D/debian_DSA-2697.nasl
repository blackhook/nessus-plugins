#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2697. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66678);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-2116");
  script_xref(name:"DSA", value:"2697");

  script_name(english:"Debian DSA-2697-1 : gnutls26 - out-of-bounds array read");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that a malicious client could crash a GNUTLS server
and vice versa, by sending TLS records encrypted with a block cipher
which contain invalid padding.

The oldstable distribution (squeeze) is not affected because the
security fix that introduced this vulnerability was not applied to it."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=709301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/gnutls26"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2013/dsa-2697"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gnutls26 packages.

For the stable distribution (wheezy), this problem has been fixed in
version 2.12.20-7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnutls26");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/30");
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
if (deb_check(release:"7.0", prefix:"gnutls-bin", reference:"2.12.20-7")) flag++;
if (deb_check(release:"7.0", prefix:"gnutls26-doc", reference:"2.12.20-7")) flag++;
if (deb_check(release:"7.0", prefix:"guile-gnutls", reference:"2.12.20-7")) flag++;
if (deb_check(release:"7.0", prefix:"libgnutls-dev", reference:"2.12.20-7")) flag++;
if (deb_check(release:"7.0", prefix:"libgnutls-openssl27", reference:"2.12.20-7")) flag++;
if (deb_check(release:"7.0", prefix:"libgnutls26", reference:"2.12.20-7")) flag++;
if (deb_check(release:"7.0", prefix:"libgnutls26-dbg", reference:"2.12.20-7")) flag++;
if (deb_check(release:"7.0", prefix:"libgnutlsxx27", reference:"2.12.20-7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
