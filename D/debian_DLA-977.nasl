#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-977-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100623);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-2015", "CVE-2015-4680", "CVE-2017-9148");
  script_bugtraq_id(65581, 75327);

  script_name(english:"Debian DLA-977-1 : freeradius security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues were discovered in FreeRADIUS, a high-performance and
highly configurable RADIUS server.

CVE-2014-2015

A stack-based buffer overflow was found in the normify function in the
rlm_pap module, which can be attacked by existing users to cause
denial of service or other issues.

CVE-2015-4680

It was discovered that freeradius failed to check revocation of
intermediate CA certificates, thus accepting client certificates
issued by revoked certificates from intermediate CAs.

Note that to enable checking of intermediate CA
certificates, it is necessary to enable the check_all_crl
option of the EAP TLS section in eap.conf. This is only
necessary for servers using certificates signed by
intermediate CAs. Servers that use self-signed CAs are
unaffected.

CVE-2017-9148

The TLS session cache fails to reliably prevent resumption of an
unauthenticated session, which allows remote attackers (such as
malicious 802.1X supplicants) to bypass authentication via PEAP or
TTLS.

For Debian 7 'Wheezy', these problems have been fixed in version
2.1.12+dfsg-1.2+deb7u1.

We recommend that you upgrade your freeradius packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/06/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/freeradius"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-dialupadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-iodbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreeradius-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreeradius2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"freeradius", reference:"2.1.12+dfsg-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"freeradius-common", reference:"2.1.12+dfsg-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"freeradius-dbg", reference:"2.1.12+dfsg-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"freeradius-dialupadmin", reference:"2.1.12+dfsg-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"freeradius-iodbc", reference:"2.1.12+dfsg-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"freeradius-krb5", reference:"2.1.12+dfsg-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"freeradius-ldap", reference:"2.1.12+dfsg-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"freeradius-mysql", reference:"2.1.12+dfsg-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"freeradius-postgresql", reference:"2.1.12+dfsg-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"freeradius-utils", reference:"2.1.12+dfsg-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libfreeradius-dev", reference:"2.1.12+dfsg-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libfreeradius2", reference:"2.1.12+dfsg-1.2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
