#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4795. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(143194);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-28196");
  script_xref(name:"DSA", value:"4795");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Debian DSA-4795-1 : krb5 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Demi Obeneour discovered that unbounded recursion in the ASN1 parser
of libkrb5 could result in denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/krb5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/krb5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4795"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the krb5 packages.

For the stable distribution (buster), this problem has been fixed in
version 1.17-3+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28196");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"krb5-admin-server", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"krb5-doc", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"krb5-gss-samples", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"krb5-k5tls", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"krb5-kdc", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"krb5-kdc-ldap", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"krb5-kpropd", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"krb5-locales", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"krb5-multidev", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"krb5-otp", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"krb5-pkinit", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"krb5-user", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libgssapi-krb5-2", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libgssrpc4", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libk5crypto3", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libkadm5clnt-mit11", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libkadm5srv-mit11", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libkdb5-9", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libkrad-dev", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libkrad0", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libkrb5-3", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libkrb5-dbg", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libkrb5-dev", reference:"1.17-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libkrb5support0", reference:"1.17-3+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
