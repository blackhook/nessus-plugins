#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1320-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108661);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-1050");

  script_name(english:"Debian DLA-1320-1 : samba security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Samba, a SMB/CIFS
file, print, and login server for Unix. The Common Vulnerabilities and
Exposures project identifies the following issues :

CVE-2018-1050

It was discovered that Samba is prone to a denial of service attack
when the RPC spoolss service is configured to be run as an external
daemon. Thanks for Jeremy Allison for the patch.

https://www.samba.org/samba/security/CVE-2018-1050.html

For Debian 7 'Wheezy', these problems have been fixed in version
3.6.6-6+deb7u16.

We recommend that you upgrade your samba packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/03/msg00024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2018-1050.html"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-smbpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-common-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:smbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/28");
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
if (deb_check(release:"7.0", prefix:"libnss-winbind", reference:"3.6.6-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-smbpass", reference:"3.6.6-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-winbind", reference:"3.6.6-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libsmbclient", reference:"3.6.6-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libsmbclient-dev", reference:"3.6.6-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libwbclient-dev", reference:"3.6.6-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libwbclient0", reference:"3.6.6-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"samba", reference:"3.6.6-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"samba-common", reference:"3.6.6-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"samba-common-bin", reference:"3.6.6-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"samba-dbg", reference:"3.6.6-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"samba-doc", reference:"3.6.6-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"samba-doc-pdf", reference:"3.6.6-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"samba-tools", reference:"3.6.6-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"smbclient", reference:"3.6.6-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"swat", reference:"3.6.6-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"winbind", reference:"3.6.6-6+deb7u16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
