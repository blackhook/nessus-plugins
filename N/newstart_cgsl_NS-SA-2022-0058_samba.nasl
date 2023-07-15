##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0058. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160772);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id("CVE-2020-1472", "CVE-2020-14318", "CVE-2020-14323");
  script_xref(name:"IAVA", value:"2020-A-0508-S");
  script_xref(name:"IAVA", value:"2020-A-0438-S");
  script_xref(name:"IAVA", value:"2020-A-0367-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2020/09/21");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0101");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0008");
  script_xref(name:"CEA-ID", value:"CEA-2020-0121");
  script_xref(name:"CEA-ID", value:"CEA-2023-0016");

  script_name(english:"NewStart CGSL MAIN 6.02 : samba Multiple Vulnerabilities (NS-SA-2022-0058)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has samba packages installed that are affected by multiple
vulnerabilities:

  - A flaw was found in the way samba handled file and directory permissions. An authenticated user could use
    this flaw to gain access to certain file and directory information which otherwise would be unavailable to
    the attacker. (CVE-2020-14318)

  - A null pointer dereference flaw was found in samba's Winbind service in versions before 4.11.15, before
    4.12.9 and before 4.13.1. A local user could use this flaw to crash the winbind service causing denial of
    service. (CVE-2020-14323)

  - An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure
    channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon
    Elevation of Privilege Vulnerability'. (CVE-2020-1472)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0058");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ctdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ctdb-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libsmbclient-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libwbclient-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-client-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-common-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-common-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-krb5-printing-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-test-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-vfs-glusterfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind-clients-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind-krb5-locator-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind-modules-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winexe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winexe-debuginfo");
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

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'ctdb-4.13.3-3.el8',
    'ctdb-debuginfo-4.13.3-3.el8',
    'ctdb-tests-4.13.3-3.el8',
    'ctdb-tests-debuginfo-4.13.3-3.el8',
    'libsmbclient-4.13.3-3.el8',
    'libsmbclient-debuginfo-4.13.3-3.el8',
    'libsmbclient-devel-4.13.3-3.el8',
    'libwbclient-4.13.3-3.el8',
    'libwbclient-debuginfo-4.13.3-3.el8',
    'libwbclient-devel-4.13.3-3.el8',
    'python3-samba-4.13.3-3.el8',
    'python3-samba-debuginfo-4.13.3-3.el8',
    'python3-samba-devel-4.13.3-3.el8',
    'python3-samba-test-4.13.3-3.el8',
    'samba-4.13.3-3.el8',
    'samba-client-4.13.3-3.el8',
    'samba-client-debuginfo-4.13.3-3.el8',
    'samba-client-libs-4.13.3-3.el8',
    'samba-client-libs-debuginfo-4.13.3-3.el8',
    'samba-common-4.13.3-3.el8',
    'samba-common-libs-4.13.3-3.el8',
    'samba-common-libs-debuginfo-4.13.3-3.el8',
    'samba-common-tools-4.13.3-3.el8',
    'samba-common-tools-debuginfo-4.13.3-3.el8',
    'samba-debuginfo-4.13.3-3.el8',
    'samba-debugsource-4.13.3-3.el8',
    'samba-devel-4.13.3-3.el8',
    'samba-krb5-printing-4.13.3-3.el8',
    'samba-krb5-printing-debuginfo-4.13.3-3.el8',
    'samba-libs-4.13.3-3.el8',
    'samba-libs-debuginfo-4.13.3-3.el8',
    'samba-pidl-4.13.3-3.el8',
    'samba-test-4.13.3-3.el8',
    'samba-test-debuginfo-4.13.3-3.el8',
    'samba-test-libs-4.13.3-3.el8',
    'samba-test-libs-debuginfo-4.13.3-3.el8',
    'samba-vfs-glusterfs-4.13.3-3.el8',
    'samba-vfs-glusterfs-debuginfo-4.13.3-3.el8',
    'samba-winbind-4.13.3-3.el8',
    'samba-winbind-clients-4.13.3-3.el8',
    'samba-winbind-clients-debuginfo-4.13.3-3.el8',
    'samba-winbind-debuginfo-4.13.3-3.el8',
    'samba-winbind-krb5-locator-4.13.3-3.el8',
    'samba-winbind-krb5-locator-debuginfo-4.13.3-3.el8',
    'samba-winbind-modules-4.13.3-3.el8',
    'samba-winbind-modules-debuginfo-4.13.3-3.el8',
    'samba-winexe-4.13.3-3.el8',
    'samba-winexe-debuginfo-4.13.3-3.el8'
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
