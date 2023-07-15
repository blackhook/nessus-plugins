#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0076. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167454);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/14");

  script_cve_id("CVE-2022-22720");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : httpd Vulnerability (NS-SA-2022-0076)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has httpd packages installed that are affected by
a vulnerability:

  - Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered
    discarding the request body, exposing the server to HTTP Request Smuggling (CVE-2022-22720)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0076");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-22720");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL httpd packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22720");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/14");

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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.04" &&
    os_release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'httpd-2.4.6-97.el7_9.5',
    'httpd-debuginfo-2.4.6-97.el7_9.5',
    'httpd-devel-2.4.6-97.el7_9.5',
    'httpd-manual-2.4.6-97.el7_9.5',
    'httpd-tools-2.4.6-97.el7_9.5',
    'mod_ldap-2.4.6-97.el7_9.5',
    'mod_proxy_html-2.4.6-97.el7_9.5',
    'mod_session-2.4.6-97.el7_9.5',
    'mod_ssl-2.4.6-97.el7_9.5'
  ],
  'CGSL MAIN 5.04': [
    'httpd-2.4.6-97.el7_9.5',
    'httpd-debuginfo-2.4.6-97.el7_9.5',
    'httpd-devel-2.4.6-97.el7_9.5',
    'httpd-manual-2.4.6-97.el7_9.5',
    'httpd-tools-2.4.6-97.el7_9.5',
    'mod_ldap-2.4.6-97.el7_9.5',
    'mod_proxy_html-2.4.6-97.el7_9.5',
    'mod_session-2.4.6-97.el7_9.5',
    'mod_ssl-2.4.6-97.el7_9.5'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'httpd');
}
