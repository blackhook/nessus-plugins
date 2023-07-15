#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0099. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167474);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id(
    "CVE-2016-2124",
    "CVE-2020-25717",
    "CVE-2021-20254",
    "CVE-2021-23192",
    "CVE-2021-43566",
    "CVE-2021-44142"
  );
  script_xref(name:"IAVA", value:"2021-A-0208-S");
  script_xref(name:"IAVA", value:"2022-A-0020-S");
  script_xref(name:"IAVA", value:"2022-A-0054-S");

  script_name(english:"NewStart CGSL MAIN 6.02 : samba Multiple Vulnerabilities (NS-SA-2022-0099)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has samba packages installed that are affected by multiple
vulnerabilities:

  - A flaw was found in the way samba implemented SMB1 authentication. An attacker could use this flaw to
    retrieve the plaintext password sent over the wire even if Kerberos authentication was required.
    (CVE-2016-2124)

  - A flaw was found in the way Samba maps domain users to local users. An authenticated attacker could use
    this flaw to cause possible privilege escalation. (CVE-2020-25717)

  - A flaw was found in samba. The Samba smbd file server must map Windows group identities (SIDs) into unix
    group ids (gids). The code that performs this had a flaw that could allow it to read data beyond the end
    of the array in the case where a negative cache entry had been added to the mapping cache. This could
    cause the calling code to return those values into the process token that stores the group membership for
    a user. The highest threat from this vulnerability is to data confidentiality and integrity.
    (CVE-2021-20254)

  - A flaw was found in the way samba implemented DCE/RPC. If a client to a Samba server sent a very large
    DCE/RPC request, and chose to fragment it, an attacker could replace later fragments with their own data,
    bypassing the signature requirements. (CVE-2021-23192)

  - All versions of Samba prior to 4.13.16 are vulnerable to a malicious client using an SMB1 or NFS race to
    allow a directory to be created in an area of the server file system not exported under the share
    definition. Note that SMB1 has to be enabled, or the share also available via NFS in order for this attack
    to succeed. (CVE-2021-43566)

  - The Samba vfs_fruit module uses extended file attributes (EA, xattr) to provide ...enhanced compatibility
    with Apple SMB clients and interoperability with a Netatalk 3 AFP fileserver. Samba versions prior to
    4.13.17, 4.14.12 and 4.15.5 with vfs_fruit configured allow out-of-bounds heap read and write via
    specially crafted extended file attributes. A remote attacker with write access to extended file
    attributes can execute arbitrary code with the privileges of smbd, typically root. (CVE-2021-44142)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0099");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2016-2124");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-25717");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-20254");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23192");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-43566");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-44142");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL samba packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44142");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'libsmbclient-4.14.5-9.el8_5',
    'libwbclient-4.14.5-9.el8_5',
    'samba-4.14.5-9.el8_5',
    'samba-client-4.14.5-9.el8_5',
    'samba-client-libs-4.14.5-9.el8_5',
    'samba-common-4.14.5-9.el8_5',
    'samba-common-libs-4.14.5-9.el8_5',
    'samba-common-tools-4.14.5-9.el8_5',
    'samba-libs-4.14.5-9.el8_5',
    'samba-winbind-4.14.5-9.el8_5',
    'samba-winbind-clients-4.14.5-9.el8_5',
    'samba-winbind-modules-4.14.5-9.el8_5'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'samba');
}
