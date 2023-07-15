#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2463-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(143186);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id("CVE-2020-10704", "CVE-2020-10730", "CVE-2020-10745", "CVE-2020-10760", "CVE-2020-14303", "CVE-2020-14318", "CVE-2020-14323", "CVE-2020-14383", "CVE-2020-1472");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2020/09/21");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0101");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0008");
  script_xref(name:"CEA-ID", value:"CEA-2020-0121");
  script_xref(name:"CEA-ID", value:"CEA-2023-0016");

  script_name(english:"Debian DLA-2463-1 : samba security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple vulnerabilities have been discovered in Samba, a SMB/CIFS
file, print, and login server for Unix.

CVE-2020-1472

Unauthenticated domain controller compromise by subverting Netlogon
cryptography. This vulnerability includes both ZeroLogon and
non-ZeroLogon variations.

CVE-2020-10704

An unauthorized user can trigger a denial of service via a stack
overflow in the AD DC LDAP server.

CVE-2020-10730

NULL pointer de-reference and use-after-free in Samba AD DC LDAP
Server with ASQ, VLV and paged_results.

CVE-2020-10745

Denial of service resulting from abuse of compression of replies to
NetBIOS over TCP/IP name resolution and DNS packets causing excessive
CPU load on the Samba AD DC.

CVE-2020-10760

The use of the paged_results or VLV controls against the Global
Catalog LDAP server on the AD DC will cause a use-after-free.

CVE-2020-14303

Denial of service resulting from CPU spin and and inability to process
further requests once the AD DC NBT server receives an empty
(zero-length) UDP packet to port 137.

CVE-2020-14318

Missing handle permissions check in ChangeNotify

CVE-2020-14323

Unprivileged user can crash winbind via invalid lookupsids DoS

CVE-2020-14383

DNS server crash via invalid records resulting from uninitialized
variables

For Debian 9 stretch, these problems have been fixed in version
2:4.5.16+dfsg-1+deb9u3.

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
    value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00041.html"
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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1472");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"ctdb", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libnss-winbind", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libpam-winbind", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libparse-pidl-perl", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libsmbclient", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libsmbclient-dev", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libwbclient-dev", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libwbclient0", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python-samba", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"registry-tools", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"samba", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"samba-common", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"samba-common-bin", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"samba-dev", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"samba-dsdb-modules", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"samba-libs", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"samba-testsuite", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"samba-vfs-modules", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"smbclient", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"winbind", reference:"2:4.5.16+dfsg-1+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
