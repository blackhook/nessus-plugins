#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1522-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117715);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-16151", "CVE-2018-16152");

  script_name(english:"Debian DLA-1522-1 : strongswan security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sze Yiu Chau and his team from Purdue University and The University of
Iowa found several security issues in the gmp plugin for strongSwan,
an IKE/IPsec suite.

CVE-2018-16151

The OID parser in the ASN.1 code in gmp allows any number of random
bytes after a valid OID.

CVE-2018-16152

The algorithmIdentifier parser in the ASN.1 code in gmp doesn't
enforce a NULL value for the optional parameter which is not used with
any PKCS#1 algorithm.

For Debian 8 'Jessie', these problems have been fixed in version
5.2.1-6+deb8u7.

We recommend that you upgrade your strongswan packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/09/msg00032.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/strongswan"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:charon-cmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcharon-extra-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstrongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstrongswan-extra-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstrongswan-standard-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-charon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-ike");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-ikev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-ikev2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-libcharon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-nm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-starter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"charon-cmd", reference:"5.2.1-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libcharon-extra-plugins", reference:"5.2.1-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libstrongswan", reference:"5.2.1-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libstrongswan-extra-plugins", reference:"5.2.1-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libstrongswan-standard-plugins", reference:"5.2.1-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan", reference:"5.2.1-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-charon", reference:"5.2.1-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-dbg", reference:"5.2.1-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-ike", reference:"5.2.1-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-ikev1", reference:"5.2.1-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-ikev2", reference:"5.2.1-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-libcharon", reference:"5.2.1-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-nm", reference:"5.2.1-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-starter", reference:"5.2.1-6+deb8u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
