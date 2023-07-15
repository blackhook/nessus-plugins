#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4055. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105087);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-17439");
  script_xref(name:"DSA", value:"4055");

  script_name(english:"Debian DSA-4055-1 : heimdal - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Michael Eder and Thomas Kittel discovered that Heimdal, an
implementation of Kerberos 5 that aims to be compatible with MIT
Kerberos, did not correctly handle ASN.1 data. This would allow an
unauthenticated remote attacker to cause a denial of service (crash of
the KDC daemon) by sending maliciously crafted packets."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=878144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/heimdal"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/heimdal"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4055"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the heimdal packages.

For the stable distribution (stretch), this problem has been fixed in
version 7.1.0+dfsg-13+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/08");
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
if (deb_check(release:"9.0", prefix:"heimdal-clients", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"heimdal-dbg", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"heimdal-dev", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"heimdal-docs", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"heimdal-kcm", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"heimdal-kdc", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"heimdal-multidev", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"heimdal-servers", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libasn1-8-heimdal", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libgssapi3-heimdal", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libhcrypto4-heimdal", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libhdb9-heimdal", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libheimbase1-heimdal", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libheimntlm0-heimdal", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libhx509-5-heimdal", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libkadm5clnt7-heimdal", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libkadm5srv8-heimdal", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libkafs0-heimdal", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libkdc2-heimdal", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libkrb5-26-heimdal", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libotp0-heimdal", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libroken18-heimdal", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libsl0-heimdal", reference:"7.1.0+dfsg-13+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libwind0-heimdal", reference:"7.1.0+dfsg-13+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
