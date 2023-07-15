#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0011. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174053);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/11");

  script_cve_id(
    "CVE-2021-26691",
    "CVE-2021-34798",
    "CVE-2021-39275",
    "CVE-2021-40438",
    "CVE-2021-44790",
    "CVE-2022-22720"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/15");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : httpd Multiple Vulnerabilities (NS-SA-2023-0011)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has httpd packages installed that are affected by
multiple vulnerabilities:

  - In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionHeader sent by an origin server
    could cause a heap overflow (CVE-2021-26691)

  - Malformed requests may cause the server to dereference a NULL pointer. This issue affects Apache HTTP
    Server 2.4.48 and earlier. (CVE-2021-34798)

  - ap_escape_quotes() may write beyond the end of a buffer when given malicious input. No included modules
    pass untrusted data to these functions, but third-party / external modules may. This issue affects Apache
    HTTP Server 2.4.48 and earlier. (CVE-2021-39275)

  - A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the
    remote user. This issue affects Apache HTTP Server 2.4.48 and earlier. (CVE-2021-40438)

  - A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser
    (r:parsebody() called from Lua scripts). The Apache httpd team is not aware of an exploit for the
    vulnerabilty though it might be possible to craft one. This issue affects Apache HTTP Server 2.4.51 and
    earlier. (CVE-2021-44790)

  - Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered
    discarding the request body, exposing the server to HTTP Request Smuggling (CVE-2022-22720)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2023-0011");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-26691");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-34798");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-39275");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-40438");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-44790");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-22720");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL httpd packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22720");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.05" &&
    os_release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'httpd-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66',
    'httpd-debuginfo-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66',
    'httpd-devel-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66',
    'httpd-manual-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66',
    'httpd-tools-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66',
    'mod_ldap-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66',
    'mod_proxy_html-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66',
    'mod_session-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66',
    'mod_ssl-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66'
  ],
  'CGSL MAIN 5.05': [
    'httpd-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66',
    'httpd-debuginfo-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66',
    'httpd-devel-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66',
    'httpd-manual-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66',
    'httpd-tools-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66',
    'mod_ldap-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66',
    'mod_proxy_html-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66',
    'mod_session-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66',
    'mod_ssl-2.4.6-97.el7_9.5.cgslv5_5.0.2.gf2adb66'
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
