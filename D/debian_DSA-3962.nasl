#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3962. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102929);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-11185");
  script_xref(name:"DSA", value:"3962");

  script_name(english:"Debian DSA-3962-1 : strongswan - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A denial of service vulnerability was identified in strongSwan, an
IKE/IPsec suite, using Google's OSS-Fuzz fuzzing project.

The gmp plugin in strongSwan had insufficient input validation when
verifying RSA signatures. This coding error could lead to a NULL
pointer dereference, leading to process crash."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=872155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/strongswan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/strongswan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3962"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the strongswan packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 5.2.1-6+deb8u5.

For the stable distribution (stretch), this problem has been fixed in
version 5.5.1-4+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/03");
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
if (deb_check(release:"8.0", prefix:"charon-cmd", reference:"5.2.1-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcharon-extra-plugins", reference:"5.2.1-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libstrongswan", reference:"5.2.1-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libstrongswan-extra-plugins", reference:"5.2.1-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libstrongswan-standard-plugins", reference:"5.2.1-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan", reference:"5.2.1-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-charon", reference:"5.2.1-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-dbg", reference:"5.2.1-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-ike", reference:"5.2.1-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-ikev1", reference:"5.2.1-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-ikev2", reference:"5.2.1-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-libcharon", reference:"5.2.1-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-nm", reference:"5.2.1-6+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-starter", reference:"5.2.1-6+deb8u5")) flag++;
if (deb_check(release:"9.0", prefix:"charon-cmd", reference:"5.5.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"charon-systemd", reference:"5.5.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcharon-extra-plugins", reference:"5.5.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libstrongswan", reference:"5.5.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libstrongswan-extra-plugins", reference:"5.5.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libstrongswan-standard-plugins", reference:"5.5.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan", reference:"5.5.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-charon", reference:"5.5.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-ike", reference:"5.5.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-ikev1", reference:"5.5.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-ikev2", reference:"5.5.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-libcharon", reference:"5.5.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-nm", reference:"5.5.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-pki", reference:"5.5.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-scepclient", reference:"5.5.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-starter", reference:"5.5.1-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-swanctl", reference:"5.5.1-4+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
