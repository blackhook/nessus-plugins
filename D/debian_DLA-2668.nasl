#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2668-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(150107);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2019-10218", "CVE-2019-14833", "CVE-2019-14847", "CVE-2019-14861", "CVE-2019-14870", "CVE-2019-14902", "CVE-2019-14907", "CVE-2021-20254");

  script_name(english:"Debian DLA-2668-1 : samba security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in Samba, SMB/CIFS file,
print, and login server for Unix

CVE-2019-10218

A flaw was found in the samba client, where a malicious server can
supply a pathname to the client with separators. This could allow the
client to access files and folders outside of the SMB network
pathnames. An attacker could use this vulnerability to create files
outside of the current working directory using the privileges of the
client user.

CVE-2019-14833

A flaw was found in Samba, in the way it handles a user password
change or a new password for a samba user. The Samba Active Directory
Domain Controller can be configured to use a custom script to check
for password complexity. This configuration can fail to verify
password complexity when non-ASCII characters are used in the
password, which could lead to weak passwords being set for samba
users, making it vulnerable to dictionary attacks.

CVE-2019-14847

A flaw was found in samba where an attacker can crash AD DC LDAP
server via dirsync resulting in denial of service. Privilege
escalation is not possible with this issue.

CVE-2019-14861

Samba have an issue, where the (poorly named) dnsserver RPC pipe
provides administrative facilities to modify DNS records and zones.
Samba, when acting as an AD DC, stores DNS records in LDAP. In AD, the
default permissions on the DNS partition allow creation of new records
by authenticated users. This is used for example to allow machines to
self-register in DNS. If a DNS record was created that
case-insensitively matched the name of the zone, the ldb_qsort() and
dns_name_compare() routines could be confused into reading memory
prior to the list of DNS entries when responding to
DnssrvEnumRecords() or DnssrvEnumRecords2() and so following invalid
memory as a pointer.

CVE-2019-14870

Samba have an issue, where the S4U (MS-SFU) Kerberos delegation model
includes a feature allowing for a subset of clients to be opted out of
constrained delegation in any way, either S4U2Self or regular Kerberos
authentication, by forcing all tickets for these clients to be
non-forwardable. In AD this is implemented by a user attribute
delegation_not_allowed (aka not-delegated), which translates to
disallow-forwardable. However the Samba AD DC does not do that for
S4U2Self and does set the forwardable flag even if the impersonated
client has the not-delegated flag set.

CVE-2019-14902

There is an issue in samba, where the removal of the right to create
or modify a subtree would not automatically be taken away on all
domain controllers.

CVE-2019-14907

samba have an issue where if it is set with 'log level = 3' (or above)
then the string obtained from the client, after a failed character
conversion, is printed. Such strings can be provided during the
NTLMSSP authentication exchange. In the Samba AD DC in particular,
this may cause a long-lived process(such as the RPC server) to
terminate. (In the file server case, the most likely target, smbd,
operates as process-per-client and so a crash there is harmless).

CVE-2021-20254

A flaw was found in samba. The Samba smbd file server must map Windows
group identities (SIDs) into unix group ids (gids). The code that
performs this had a flaw that could allow it to read data beyond the
end of the array in the case where a negative cache entry had been
added to the mapping cache. This could cause the calling code to
return those values into the process token that stores the group
membership for a user. The highest threat from this vulnerability is
to data confidentiality and integrity.

For Debian 9 stretch, these problems have been fixed in version
2:4.5.16+dfsg-1+deb9u4.

We recommend that you upgrade your samba packages.

For the detailed security status of samba please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/samba

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/05/msg00023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/samba"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14870");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libparse-pidl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:registry-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-common-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-dsdb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-vfs-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:smbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"ctdb", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libnss-winbind", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libpam-winbind", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libparse-pidl-perl", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libsmbclient", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libsmbclient-dev", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwbclient-dev", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwbclient0", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python-samba", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"registry-tools", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"samba", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"samba-common", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"samba-common-bin", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"samba-dev", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"samba-dsdb-modules", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"samba-libs", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"samba-testsuite", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"samba-vfs-modules", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"smbclient", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"winbind", reference:"2:4.5.16+dfsg-1+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
