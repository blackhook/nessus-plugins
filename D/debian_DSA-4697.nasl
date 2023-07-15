#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4697. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(137209);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id("CVE-2020-13777");
  script_xref(name:"DSA", value:"4697");

  script_name(english:"Debian DSA-4697-1 : gnutls28 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A flaw was reported in the TLS session ticket key construction in
GnuTLS, a library implementing the TLS and SSL protocols. The flaw
caused the TLS server to not securely construct a session ticket
encryption key considering the application supplied secret, allowing a
man-in-the-middle attacker to bypass authentication in TLS 1.3 and
recover previous conversations in TLS 1.2."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=962289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/gnutls28"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/gnutls28"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4697"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the gnutls28 packages.

For the stable distribution (buster), this problem has been fixed in
version 3.6.7-4+deb10u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13777");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnutls28");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"gnutls-bin", reference:"3.6.7-4+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"gnutls-doc", reference:"3.6.7-4+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"libgnutls-dane0", reference:"3.6.7-4+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"libgnutls-openssl27", reference:"3.6.7-4+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"libgnutls28-dev", reference:"3.6.7-4+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"libgnutls30", reference:"3.6.7-4+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"libgnutlsxx28", reference:"3.6.7-4+deb10u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
