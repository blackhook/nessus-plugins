##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0111. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144008);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/10");

  script_cve_id("CVE-2019-10195", "CVE-2019-14867");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : ipa Multiple Vulnerabilities (NS-SA-2020-0111)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has ipa packages installed that are affected by
multiple vulnerabilities:

  - A flaw was found in IPA, all 4.6.x versions before 4.6.7, all 4.7.x versions before 4.7.4 and all 4.8.x
    versions before 4.8.3, in the way that FreeIPA's batch processing API logged operations. This included
    passing user passwords in clear text on FreeIPA masters. Batch processing of commands with passwords as
    arguments or options is not performed by default in FreeIPA but is possible by third-party components. An
    attacker having access to system logs on FreeIPA masters could use this flaw to produce log file content
    with passwords exposed. (CVE-2019-10195)

  - A flaw was found in IPA, all 4.6.x versions before 4.6.7, all 4.7.x versions before 4.7.4 and all 4.8.x
    versions before 4.8.3, in the way the internal function ber_scanf() was used in some components of the IPA
    server, which parsed kerberos key data. An unauthenticated attacker who could trigger parsing of the krb
    principal key could cause the IPA server to crash or in some conditions, cause arbitrary code to be
    executed on the server hosting the IPA server. (CVE-2019-14867)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0111");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL ipa packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14867");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'ipa-client-4.6.5-11.el7.centos.4',
    'ipa-client-common-4.6.5-11.el7.centos.4',
    'ipa-common-4.6.5-11.el7.centos.4',
    'ipa-debuginfo-4.6.5-11.el7.centos.4',
    'ipa-python-compat-4.6.5-11.el7.centos.4',
    'ipa-server-4.6.5-11.el7.centos.4',
    'ipa-server-common-4.6.5-11.el7.centos.4',
    'ipa-server-dns-4.6.5-11.el7.centos.4',
    'ipa-server-trust-ad-4.6.5-11.el7.centos.4',
    'python2-ipaclient-4.6.5-11.el7.centos.4',
    'python2-ipalib-4.6.5-11.el7.centos.4',
    'python2-ipaserver-4.6.5-11.el7.centos.4'
  ],
  'CGSL MAIN 5.05': [
    'ipa-client-4.6.5-11.el7.centos.4',
    'ipa-client-common-4.6.5-11.el7.centos.4',
    'ipa-common-4.6.5-11.el7.centos.4',
    'ipa-debuginfo-4.6.5-11.el7.centos.4',
    'ipa-python-compat-4.6.5-11.el7.centos.4',
    'ipa-server-4.6.5-11.el7.centos.4',
    'ipa-server-common-4.6.5-11.el7.centos.4',
    'ipa-server-dns-4.6.5-11.el7.centos.4',
    'ipa-server-trust-ad-4.6.5-11.el7.centos.4',
    'python2-ipaclient-4.6.5-11.el7.centos.4',
    'python2-ipalib-4.6.5-11.el7.centos.4',
    'python2-ipaserver-4.6.5-11.el7.centos.4'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ipa');
}
