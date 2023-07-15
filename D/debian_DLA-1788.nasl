#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1788-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125174);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-16860");

  script_name(english:"Debian DLA-1788-1 : samba security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Isaac Boukris and Andrew Bartlett discovered that the S4U2Self
Kerberos extension used in Samba's Active Directory support was
susceptible to man-in-the-middle attacks caused by incomplete checksum
validation.

For Debian 8 'Jessie', this problem has been fixed in version
2:4.2.14+dfsg-0+deb8u13.

We recommend that you upgrade your samba packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/05/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/samba"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-smbpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libparse-pidl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbsharemodes-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbsharemodes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:registry-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-common-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-dsdb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-vfs-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:smbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libnss-winbind", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-smbpass", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-winbind", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libparse-pidl-perl", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbclient", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbclient-dev", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbsharemodes-dev", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbsharemodes0", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libwbclient-dev", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"libwbclient0", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"python-samba", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"registry-tools", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"samba", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"samba-common", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"samba-common-bin", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"samba-dbg", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"samba-dev", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"samba-doc", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"samba-dsdb-modules", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"samba-libs", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"samba-testsuite", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"samba-vfs-modules", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"smbclient", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;
if (deb_check(release:"8.0", prefix:"winbind", reference:"2:4.2.14+dfsg-0+deb8u13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
