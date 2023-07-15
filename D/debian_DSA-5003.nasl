#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5003. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155015);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id(
    "CVE-2016-2124",
    "CVE-2020-25717",
    "CVE-2020-25718",
    "CVE-2020-25719",
    "CVE-2020-25721",
    "CVE-2020-25722",
    "CVE-2021-3738",
    "CVE-2021-23192"
  );
  script_xref(name:"IAVA", value:"2021-A-0554-S");

  script_name(english:"Debian DSA-5003-1 : samba - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5003 advisory.

  - Multiple flaws were found in the way samba AD DC implemented access and conformance checking of stored
    data. An attacker could use this flaw to cause total domain compromise. (CVE-2020-25722)

  - A flaw was found in the way samba implemented SMB1 authentication. An attacker could use this flaw to
    retrieve the plaintext password sent over the wire even if Kerberos authentication was required.
    (CVE-2016-2124)

  - A flaw was found in the way Samba maps domain users to local users. An authenticated attacker could use
    this flaw to cause possible privilege escalation. (CVE-2020-25717)

  - A flaw was found in the way samba, as an Active Directory Domain Controller, is able to support an RODC
    (read-only domain controller). This would allow an RODC to print administrator tickets. (CVE-2020-25718)

  - A flaw was found in the way Samba, as an Active Directory Domain Controller, implemented Kerberos name-
    based authentication. The Samba AD DC, could become confused about the user a ticket represents if it did
    not strictly require a Kerberos PAC and always use the SIDs found within. The result could include total
    domain compromise. (CVE-2020-25719)

Note that Nessus has not tested for this issue but has instead relied only on the application's self- reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/samba");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-5003");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2016-2124");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25717");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25718");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25719");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25721");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25722");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23192");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3738");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/samba");
  script_set_attribute(attribute:"solution", value:
"Upgrade the samba packages.

For the stable distribution (bullseye), these problems have been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25719");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3738");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-samba");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'ctdb', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'libnss-winbind', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'libpam-winbind', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'libsmbclient', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'libsmbclient-dev', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'libwbclient-dev', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'libwbclient0', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'python3-samba', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'registry-tools', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'samba', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'samba-common', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'samba-common-bin', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'samba-dev', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'samba-dsdb-modules', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'samba-libs', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'samba-testsuite', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'samba-vfs-modules', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'smbclient', 'reference': '2:4.13.13+dfsg-1~deb11u2'},
    {'release': '11.0', 'prefix': 'winbind', 'reference': '2:4.13.13+dfsg-1~deb11u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libnss-winbind / libpam-winbind / libsmbclient / etc');
}
