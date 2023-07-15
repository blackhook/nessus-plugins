#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0167. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154485);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id(
    "CVE-2019-14907",
    "CVE-2020-1472",
    "CVE-2020-14318",
    "CVE-2020-14323"
  );
  script_xref(name:"IAVA", value:"2020-A-0035-S");
  script_xref(name:"IAVA", value:"2020-A-0508-S");
  script_xref(name:"IAVA", value:"2020-A-0438-S");
  script_xref(name:"IAVA", value:"2020-A-0367-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2020/09/21");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0101");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0008");
  script_xref(name:"CEA-ID", value:"CEA-2020-0121");
  script_xref(name:"CEA-ID", value:"CEA-2023-0016");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : samba Multiple Vulnerabilities (NS-SA-2021-0167)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has samba packages installed that are affected by
multiple vulnerabilities:

  - All samba versions 4.9.x before 4.9.18, 4.10.x before 4.10.12 and 4.11.x before 4.11.5 have an issue where
    if it is set with log level = 3 (or above) then the string obtained from the client, after a failed
    character conversion, is printed. Such strings can be provided during the NTLMSSP authentication exchange.
    In the Samba AD DC in particular, this may cause a long-lived process(such as the RPC server) to
    terminate. (In the file server case, the most likely target, smbd, operates as process-per-client and so a
    crash there is harmless). (CVE-2019-14907)

  - A flaw was found in the way samba handled file and directory permissions. An authenticated user could use
    this flaw to gain access to certain file and directory information which otherwise would be unavailable to
    the attacker. (CVE-2020-14318)

  - A null pointer dereference flaw was found in samba's Winbind service in versions before 4.11.15, before
    4.12.9 and before 4.13.1. A local user could use this flaw to crash the winbind service causing denial of
    service. (CVE-2020-14323)

  - An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure
    channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon
    Elevation of Privilege Vulnerability'. (CVE-2020-1472)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0167");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-14907");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14318");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14323");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-1472");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL samba packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1472");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'ctdb-4.10.16-9.el7_9',
    'ctdb-tests-4.10.16-9.el7_9',
    'libsmbclient-4.10.16-9.el7_9',
    'libsmbclient-devel-4.10.16-9.el7_9',
    'libwbclient-4.10.16-9.el7_9',
    'libwbclient-devel-4.10.16-9.el7_9',
    'samba-4.10.16-9.el7_9',
    'samba-client-4.10.16-9.el7_9',
    'samba-client-libs-4.10.16-9.el7_9',
    'samba-common-4.10.16-9.el7_9',
    'samba-common-libs-4.10.16-9.el7_9',
    'samba-common-tools-4.10.16-9.el7_9',
    'samba-dc-4.10.16-9.el7_9',
    'samba-dc-libs-4.10.16-9.el7_9',
    'samba-devel-4.10.16-9.el7_9',
    'samba-krb5-printing-4.10.16-9.el7_9',
    'samba-libs-4.10.16-9.el7_9',
    'samba-pidl-4.10.16-9.el7_9',
    'samba-python-4.10.16-9.el7_9',
    'samba-python-test-4.10.16-9.el7_9',
    'samba-test-4.10.16-9.el7_9',
    'samba-test-libs-4.10.16-9.el7_9',
    'samba-vfs-glusterfs-4.10.16-9.el7_9',
    'samba-winbind-4.10.16-9.el7_9',
    'samba-winbind-clients-4.10.16-9.el7_9',
    'samba-winbind-krb5-locator-4.10.16-9.el7_9',
    'samba-winbind-modules-4.10.16-9.el7_9'
  ],
  'CGSL MAIN 5.05': [
    'libsmbclient-4.10.16-9.el7_9',
    'libwbclient-4.10.16-9.el7_9',
    'libwbclient-devel-4.10.16-9.el7_9',
    'samba-4.10.16-9.el7_9',
    'samba-client-4.10.16-9.el7_9',
    'samba-client-libs-4.10.16-9.el7_9',
    'samba-common-4.10.16-9.el7_9',
    'samba-common-libs-4.10.16-9.el7_9',
    'samba-common-tools-4.10.16-9.el7_9',
    'samba-dc-4.10.16-9.el7_9',
    'samba-dc-libs-4.10.16-9.el7_9',
    'samba-devel-4.10.16-9.el7_9',
    'samba-krb5-printing-4.10.16-9.el7_9',
    'samba-libs-4.10.16-9.el7_9',
    'samba-pidl-4.10.16-9.el7_9',
    'samba-python-4.10.16-9.el7_9',
    'samba-python-test-4.10.16-9.el7_9',
    'samba-test-4.10.16-9.el7_9',
    'samba-test-libs-4.10.16-9.el7_9',
    'samba-vfs-glusterfs-4.10.16-9.el7_9',
    'samba-winbind-4.10.16-9.el7_9',
    'samba-winbind-clients-4.10.16-9.el7_9',
    'samba-winbind-krb5-locator-4.10.16-9.el7_9',
    'samba-winbind-modules-4.10.16-9.el7_9'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
