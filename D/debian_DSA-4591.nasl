#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4591. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132347);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/06");

  script_cve_id("CVE-2019-19906");
  script_xref(name:"DSA", value:"4591");

  script_name(english:"Debian DSA-4591-1 : cyrus-sasl2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stephan Zeisberg reported an out-of-bounds write vulnerability in the
_sasl_add_string() function in cyrus-sasl2, a library implementing the
Simple Authentication and Security Layer. A remote attacker can take
advantage of this issue to cause denial-of-service conditions for
applications using the library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=947043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/cyrus-sasl2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/cyrus-sasl2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/cyrus-sasl2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4591"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cyrus-sasl2 packages.

For the oldstable distribution (stretch), this problem has been fixed
in version 2.1.27~101-g0780600+dfsg-3+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 2.1.27+dfsg-1+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19906");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-sasl2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"cyrus-sasl2-doc", reference:"2.1.27+dfsg-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsasl2-2", reference:"2.1.27+dfsg-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsasl2-dev", reference:"2.1.27+dfsg-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsasl2-modules", reference:"2.1.27+dfsg-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsasl2-modules-db", reference:"2.1.27+dfsg-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsasl2-modules-gssapi-heimdal", reference:"2.1.27+dfsg-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsasl2-modules-gssapi-mit", reference:"2.1.27+dfsg-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsasl2-modules-ldap", reference:"2.1.27+dfsg-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsasl2-modules-otp", reference:"2.1.27+dfsg-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libsasl2-modules-sql", reference:"2.1.27+dfsg-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"sasl2-bin", reference:"2.1.27+dfsg-1+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-sasl2-doc", reference:"2.1.27~101-g0780600+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsasl2-2", reference:"2.1.27~101-g0780600+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsasl2-dev", reference:"2.1.27~101-g0780600+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsasl2-modules", reference:"2.1.27~101-g0780600+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsasl2-modules-db", reference:"2.1.27~101-g0780600+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsasl2-modules-gssapi-heimdal", reference:"2.1.27~101-g0780600+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsasl2-modules-gssapi-mit", reference:"2.1.27~101-g0780600+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsasl2-modules-ldap", reference:"2.1.27~101-g0780600+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsasl2-modules-otp", reference:"2.1.27~101-g0780600+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsasl2-modules-sql", reference:"2.1.27~101-g0780600+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"sasl2-bin", reference:"2.1.27~101-g0780600+dfsg-3+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
