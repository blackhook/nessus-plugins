#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4229. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110570);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_cve_id("CVE-2018-10811", "CVE-2018-5388");
  script_xref(name:"DSA", value:"4229");

  script_name(english:"Debian DSA-4229-1 : strongswan - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in strongSwan, an IKE/IPsec suite.

  - CVE-2018-5388
    The stroke plugin did not verify the message length when
    reading from its control socket. This vulnerability
    could lead to denial of service. On Debian write access
    to the socket requires root permission on default
    configuration.

  - CVE-2018-10811
    A missing variable initialization in IKEv2 key
    derivation could lead to a denial of service (crash of
    the charon IKE daemon) if the openssl plugin is used in
    FIPS mode and the negotiated PRF is HMAC-MD5."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-5388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-10811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/strongswan"
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
    value:"https://www.debian.org/security/2018/dsa-4229"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the strongswan packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 5.2.1-6+deb8u6.

For the stable distribution (stretch), these problems have been fixed
in version 5.5.1-4+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/18");
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
if (deb_check(release:"8.0", prefix:"charon-cmd", reference:"5.2.1-6+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libcharon-extra-plugins", reference:"5.2.1-6+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libstrongswan", reference:"5.2.1-6+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libstrongswan-extra-plugins", reference:"5.2.1-6+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libstrongswan-standard-plugins", reference:"5.2.1-6+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan", reference:"5.2.1-6+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-charon", reference:"5.2.1-6+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-dbg", reference:"5.2.1-6+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-ike", reference:"5.2.1-6+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-ikev1", reference:"5.2.1-6+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-ikev2", reference:"5.2.1-6+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-libcharon", reference:"5.2.1-6+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-nm", reference:"5.2.1-6+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-starter", reference:"5.2.1-6+deb8u6")) flag++;
if (deb_check(release:"9.0", prefix:"charon-cmd", reference:"5.5.1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"charon-systemd", reference:"5.5.1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcharon-extra-plugins", reference:"5.5.1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libstrongswan", reference:"5.5.1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libstrongswan-extra-plugins", reference:"5.5.1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libstrongswan-standard-plugins", reference:"5.5.1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan", reference:"5.5.1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-charon", reference:"5.5.1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-ike", reference:"5.5.1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-ikev1", reference:"5.5.1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-ikev2", reference:"5.5.1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-libcharon", reference:"5.5.1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-nm", reference:"5.5.1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-pki", reference:"5.5.1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-scepclient", reference:"5.5.1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-starter", reference:"5.5.1-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"strongswan-swanctl", reference:"5.5.1-4+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
