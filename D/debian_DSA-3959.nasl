#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3959. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102826);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-0379");
  script_xref(name:"DSA", value:"3959");

  script_name(english:"Debian DSA-3959-1 : libgcrypt20 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Daniel Genkin, Luke Valenta and Yuval Yarom discovered that Libgcrypt
is prone to a local side-channel attack against the ECDH encryption
with Curve25519, allowing recovery of the private key.

See https://eprint.iacr.org/2017/806 for details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=873383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://eprint.iacr.org/2017/806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libgcrypt20"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3959"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libgcrypt20 packages.

For the stable distribution (stretch), this problem has been fixed in
version 1.7.6-2+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgcrypt20");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/30");
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
if (deb_check(release:"9.0", prefix:"libgcrypt-mingw-w64-dev", reference:"1.7.6-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libgcrypt11-dev", reference:"1.7.6-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libgcrypt20", reference:"1.7.6-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libgcrypt20-dev", reference:"1.7.6-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libgcrypt20-doc", reference:"1.7.6-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libgcrypt20-udeb", reference:"1.7.6-2+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
