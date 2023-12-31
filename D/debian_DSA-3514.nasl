#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3514. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89876);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-7560", "CVE-2016-0771");
  script_xref(name:"DSA", value:"3514");

  script_name(english:"Debian DSA-3514-1 : samba - security update");
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

  - CVE-2015-7560
    Jeremy Allison of Google, Inc. and the Samba Team
    discovered that Samba incorrectly handles getting and
    setting ACLs on a symlink path. An authenticated
    malicious client can use SMB1 UNIX extensions to create
    a symlink to a file or directory, and then use non-UNIX
    SMB1 calls to overwrite the contents of the ACL on the
    file or directory linked to.

  - CVE-2016-0771
    Garming Sam and Douglas Bagnall of Catalyst IT
    discovered that Samba is vulnerable to an out-of-bounds
    read issue during DNS TXT record handling, if Samba is
    deployed as an AD DC and chosen to run the internal DNS
    server. A remote attacker can exploit this flaw to cause
    a denial of service (Samba crash), or potentially, to
    allow leakage of memory from the server in the form of a
    DNS TXT reply.

Additionally this update includes a fix for a regression introduced
due to the upstream fix for CVE-2015-5252 in DSA-3433-1 in setups
where the share path is '/'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=812429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3514"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 2:3.6.6-6+deb7u7. The oldstable distribution (wheezy)
is not affected by CVE-2016-0771.

For the stable distribution (jessie), these problems have been fixed
in version 2:4.1.17+dfsg-2+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"libnss-winbind", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-smbpass", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-winbind", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libsmbclient", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libsmbclient-dev", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libwbclient-dev", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libwbclient0", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"samba", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"samba-common", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"samba-common-bin", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"samba-dbg", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"samba-doc", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"samba-doc-pdf", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"samba-tools", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"smbclient", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"swat", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"winbind", reference:"2:3.6.6-6+deb7u7")) flag++;
if (deb_check(release:"8.0", prefix:"libnss-winbind", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-smbpass", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-winbind", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libparse-pidl-perl", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbclient", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbclient-dev", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbsharemodes-dev", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbsharemodes0", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libwbclient-dev", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libwbclient0", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-samba", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"registry-tools", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-common", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-common-bin", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-dbg", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-dev", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-doc", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-dsdb-modules", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-libs", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-testsuite", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-vfs-modules", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"smbclient", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"winbind", reference:"2:4.1.17+dfsg-2+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
