#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1429-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111111);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-10852");

  script_name(english:"Debian DLA-1429-1 : sssd security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The UNIX pipe which sudo uses to contact SSSD and read the available
sudo rules from SSSD has too wide permissions, which means that anyone
who can send a message using the same raw protocol that sudo and SSSD
use can read the sudo rules available for any user.

For Debian 8 'Jessie', these problems have been fixed in version
1.11.7-3+deb8u1.

We recommend that you upgrade your sssd packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/sssd"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libipa-hbac-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libipa-hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-idmap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-nss-idmap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-nss-idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libipa-hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libsss-nss-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-ad-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/17");
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
if (deb_check(release:"8.0", prefix:"libipa-hbac-dev", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libipa-hbac0", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libnss-sss", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-sss", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsss-idmap-dev", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsss-idmap0", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsss-nss-idmap-dev", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsss-nss-idmap0", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsss-sudo", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"python-libipa-hbac", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"python-libsss-nss-idmap", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"python-sss", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sssd", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-ad", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-ad-common", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-common", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-dbus", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-ipa", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-krb5", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-krb5-common", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-ldap", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-proxy", reference:"1.11.7-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sssd-tools", reference:"1.11.7-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
