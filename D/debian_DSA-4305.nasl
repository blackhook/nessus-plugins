#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4305. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117678);
  script_version("1.4");
  script_cvs_date("Date: 2018/12/20 11:08:44");

  script_cve_id("CVE-2018-16151", "CVE-2018-16152");
  script_xref(name:"DSA", value:"4305");

  script_name(english:"Debian DSA-4305-1 : strongswan - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sze Yiu Chau and his team from Purdue University and The University of
Iowa found several issues in the gmp plugin for strongSwan, an
IKE/IPsec suite.

Problems in the parsing and verification of RSA signatures could lead
to a Bleichenbacher-style low-exponent signature forgery in
certificates and during IKE authentication.

While the gmp plugin doesn't allow arbitrary data after the ASN.1
structure (the original Bleichenbacher attack), the ASN.1 parser is
not strict enough and allows data in specific fields inside the ASN.1
structure.

Only installations using the gmp plugin are affected (on Debian
OpenSSL plugin has priority over GMP one for RSA operations), and only
when using keys and certificates (including ones from CAs) using keys
with an exponent e = 3, which is usually rare in practice.

  - CVE-2018-16151
    The OID parser in the ASN.1 code in gmp allows any
    number of random bytes after a valid OID.

  - CVE-2018-16152
    The algorithmIdentifier parser in the ASN.1 code in gmp
    doesn't enforce a NULL value for the optional parameter
    which is not used with any PKCS#1 algorithm."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/strongswan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/strongswan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4305"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the strongswan packages.

For the stable distribution (stretch), these problems have been fixed
in version 5.5.1-4+deb9u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"charon-cmd", reference:"5.5.1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"charon-systemd", reference:"5.5.1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libcharon-extra-plugins", reference:"5.5.1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libstrongswan", reference:"5.5.1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libstrongswan-extra-plugins", reference:"5.5.1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libstrongswan-standard-plugins", reference:"5.5.1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan", reference:"5.5.1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-charon", reference:"5.5.1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-ike", reference:"5.5.1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-ikev1", reference:"5.5.1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-ikev2", reference:"5.5.1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-libcharon", reference:"5.5.1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-nm", reference:"5.5.1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-pki", reference:"5.5.1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-scepclient", reference:"5.5.1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-starter", reference:"5.5.1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-swanctl", reference:"5.5.1-4+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
