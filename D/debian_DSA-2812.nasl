#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2812. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71275);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-4408", "CVE-2013-4475");
  script_bugtraq_id(63646);
  script_xref(name:"DSA", value:"2812");

  script_name(english:"Debian DSA-2812-1 : samba - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two security issues were found in Samba, a SMB/CIFS file, print, and
login server :

  - CVE-2013-4408
    It was discovered that multiple buffer overflows in the
    processing of DCE-RPC packets may lead to the execution
    of arbitrary code.

  - CVE-2013-4475
    Hemanth Thummala discovered that ACLs were not checked
    when opening files with alternate data streams. This
    issue is only exploitable if the VFS modules
    vfs_streams_depot and/or vfs_streams_xattr are used."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2013/dsa-2812"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 3.5.6~dfsg-3squeeze11.

For the stable distribution (wheezy), these problems have been fixed
in version 3.6.6-6+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"libpam-smbpass", reference:"3.5.6~dfsg-3squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"libsmbclient", reference:"3.5.6~dfsg-3squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"libsmbclient-dev", reference:"3.5.6~dfsg-3squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"libwbclient0", reference:"3.5.6~dfsg-3squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"samba", reference:"3.5.6~dfsg-3squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"samba-common", reference:"3.5.6~dfsg-3squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"samba-common-bin", reference:"3.5.6~dfsg-3squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"samba-dbg", reference:"3.5.6~dfsg-3squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"samba-doc", reference:"3.5.6~dfsg-3squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"samba-doc-pdf", reference:"3.5.6~dfsg-3squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"samba-tools", reference:"3.5.6~dfsg-3squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"smbclient", reference:"3.5.6~dfsg-3squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"swat", reference:"3.5.6~dfsg-3squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"winbind", reference:"3.5.6~dfsg-3squeeze11")) flag++;
if (deb_check(release:"7.0", prefix:"libnss-winbind", reference:"3.6.6-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-smbpass", reference:"3.6.6-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-winbind", reference:"3.6.6-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libsmbclient", reference:"3.6.6-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libsmbclient-dev", reference:"3.6.6-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libwbclient-dev", reference:"3.6.6-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libwbclient0", reference:"3.6.6-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"samba", reference:"3.6.6-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"samba-common", reference:"3.6.6-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"samba-common-bin", reference:"3.6.6-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"samba-dbg", reference:"3.6.6-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"samba-doc", reference:"3.6.6-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"samba-doc-pdf", reference:"3.6.6-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"samba-tools", reference:"3.6.6-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"smbclient", reference:"3.6.6-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"swat", reference:"3.6.6-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"winbind", reference:"3.6.6-6+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
