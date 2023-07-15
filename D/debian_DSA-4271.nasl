#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4271. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111706);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_cve_id("CVE-2018-10858", "CVE-2018-10919");
  script_xref(name:"DSA", value:"4271");

  script_name(english:"Debian DSA-4271-1 : samba - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Samba, a SMB/CIFS
file, print, and login server for Unix. The Common Vulnerabilities and
Exposures project identifies the following issues :

  - CVE-2018-10858
    Svyatoslav Phirsov discovered that insufficient input
    validation in libsmbclient allowed a malicious Samba
    server to write to the client's heap memory.

  - CVE-2018-10919
    Phillip Kuhrt discovered that Samba when acting as an
    Active Domain controller disclosed some sensitive
    attributes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-10858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-10919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4271"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages.

For the stable distribution (stretch), these problems have been fixed
in version 2:4.5.12+dfsg-2+deb9u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/15");
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
if (deb_check(release:"9.0", prefix:"ctdb", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libnss-winbind", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libpam-winbind", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libparse-pidl-perl", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libsmbclient", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libsmbclient-dev", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libwbclient-dev", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libwbclient0", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python-samba", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"registry-tools", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"samba", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"samba-common", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"samba-common-bin", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"samba-dev", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"samba-dsdb-modules", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"samba-libs", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"samba-testsuite", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"samba-vfs-modules", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"smbclient", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"winbind", reference:"2:4.5.12+dfsg-2+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
