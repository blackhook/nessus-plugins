##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0106. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145703);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/02");

  script_cve_id("CVE-2019-10197", "CVE-2019-10218");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : samba Multiple Vulnerabilities (NS-SA-2020-0106)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has samba packages installed that are affected by
multiple vulnerabilities:

  - A flaw was found in samba versions 4.9.x up to 4.9.13, samba 4.10.x up to 4.10.8 and samba 4.11.x up to
    4.11.0rc3, when certain parameters were set in the samba configuration file. An unauthenticated attacker
    could use this flaw to escape the shared directory and access the contents of directories outside the
    share. (CVE-2019-10197)

  - A flaw was found in the samba client, all samba versions before samba 4.11.2, 4.10.10 and 4.9.15, where a
    malicious server can supply a pathname to the client with separators. This could allow the client to
    access files and folders outside of the SMB network pathnames. An attacker could use this vulnerability to
    create files outside of the current working directory using the privileges of the client user.
    (CVE-2019-10218)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0106");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL samba packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10197");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.05': [
    'ctdb-4.10.4-10.el7',
    'ctdb-tests-4.10.4-10.el7',
    'libsmbclient-4.10.4-10.el7',
    'libsmbclient-devel-4.10.4-10.el7',
    'libwbclient-4.10.4-10.el7',
    'libwbclient-devel-4.10.4-10.el7',
    'samba-4.10.4-10.el7',
    'samba-client-4.10.4-10.el7',
    'samba-client-libs-4.10.4-10.el7',
    'samba-common-4.10.4-10.el7',
    'samba-common-libs-4.10.4-10.el7',
    'samba-common-tools-4.10.4-10.el7',
    'samba-dc-4.10.4-10.el7',
    'samba-dc-libs-4.10.4-10.el7',
    'samba-debuginfo-4.10.4-10.el7',
    'samba-devel-4.10.4-10.el7',
    'samba-krb5-printing-4.10.4-10.el7',
    'samba-libs-4.10.4-10.el7',
    'samba-pidl-4.10.4-10.el7',
    'samba-python-4.10.4-10.el7',
    'samba-python-test-4.10.4-10.el7',
    'samba-test-4.10.4-10.el7',
    'samba-test-libs-4.10.4-10.el7',
    'samba-vfs-glusterfs-4.10.4-10.el7',
    'samba-winbind-4.10.4-10.el7',
    'samba-winbind-clients-4.10.4-10.el7',
    'samba-winbind-krb5-locator-4.10.4-10.el7',
    'samba-winbind-modules-4.10.4-10.el7'
  ],
  'CGSL MAIN 5.05': [
    'ctdb-4.10.4-10.el7',
    'ctdb-tests-4.10.4-10.el7',
    'libsmbclient-4.10.4-10.el7',
    'libsmbclient-devel-4.10.4-10.el7',
    'libwbclient-4.10.4-10.el7',
    'libwbclient-devel-4.10.4-10.el7',
    'samba-4.10.4-10.el7',
    'samba-client-4.10.4-10.el7',
    'samba-client-libs-4.10.4-10.el7',
    'samba-common-4.10.4-10.el7',
    'samba-common-libs-4.10.4-10.el7',
    'samba-common-tools-4.10.4-10.el7',
    'samba-dc-4.10.4-10.el7',
    'samba-dc-libs-4.10.4-10.el7',
    'samba-debuginfo-4.10.4-10.el7',
    'samba-devel-4.10.4-10.el7',
    'samba-krb5-printing-4.10.4-10.el7',
    'samba-libs-4.10.4-10.el7',
    'samba-pidl-4.10.4-10.el7',
    'samba-python-4.10.4-10.el7',
    'samba-python-test-4.10.4-10.el7',
    'samba-test-4.10.4-10.el7',
    'samba-test-libs-4.10.4-10.el7',
    'samba-vfs-glusterfs-4.10.4-10.el7',
    'samba-winbind-4.10.4-10.el7',
    'samba-winbind-clients-4.10.4-10.el7',
    'samba-winbind-krb5-locator-4.10.4-10.el7',
    'samba-winbind-modules-4.10.4-10.el7'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'samba');
}
