##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0016. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160821);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-40438");
  script_xref(name:"IAVA", value:"2022-A-0029");
  script_xref(name:"IAVA", value:"2022-A-0165");
  script_xref(name:"IAVA", value:"2021-A-0440-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/15");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : httpd Vulnerability (NS-SA-2022-0016)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has httpd packages installed that are affected by
a vulnerability:

  - A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the
    remote user. This issue affects Apache HTTP Server 2.4.48 and earlier. (CVE-2021-40438)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0016");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-40438");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL httpd packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40438");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
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

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'httpd-2.4.6-97.el7.centos.1',
    'httpd-debuginfo-2.4.6-97.el7.centos.1',
    'httpd-devel-2.4.6-97.el7.centos.1',
    'httpd-manual-2.4.6-97.el7.centos.1',
    'httpd-tools-2.4.6-97.el7.centos.1',
    'mod_ldap-2.4.6-97.el7.centos.1',
    'mod_proxy_html-2.4.6-97.el7.centos.1',
    'mod_session-2.4.6-97.el7.centos.1',
    'mod_ssl-2.4.6-97.el7.centos.1'
  ],
  'CGSL MAIN 5.04': [
    'httpd-2.4.6-97.el7.centos.1',
    'httpd-debuginfo-2.4.6-97.el7.centos.1',
    'httpd-devel-2.4.6-97.el7.centos.1',
    'httpd-manual-2.4.6-97.el7.centos.1',
    'httpd-tools-2.4.6-97.el7.centos.1',
    'mod_ldap-2.4.6-97.el7.centos.1',
    'mod_proxy_html-2.4.6-97.el7.centos.1',
    'mod_session-2.4.6-97.el7.centos.1',
    'mod_ssl-2.4.6-97.el7.centos.1'
  ]
};
var pkg_list = pkgs[release];

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'httpd');
}
