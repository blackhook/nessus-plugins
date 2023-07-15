#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0171. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154495);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2015-9251",
    "CVE-2016-10735",
    "CVE-2018-14040",
    "CVE-2018-14042",
    "CVE-2018-20676",
    "CVE-2018-20677",
    "CVE-2019-8331",
    "CVE-2019-11358",
    "CVE-2020-1722",
    "CVE-2020-11022"
  );
  script_xref(name:"IAVA", value:"2018-A-0336-S");
  script_xref(name:"IAVA", value:"2019-A-0256-S");
  script_xref(name:"IAVA", value:"2019-A-0021-S");
  script_xref(name:"IAVA", value:"2019-A-0020-S");
  script_xref(name:"IAVA", value:"2019-A-0128");
  script_xref(name:"IAVA", value:"2020-A-0017");
  script_xref(name:"IAVA", value:"2020-A-0150");
  script_xref(name:"IAVA", value:"2019-A-0384");
  script_xref(name:"IAVA", value:"2021-A-0032");
  script_xref(name:"IAVA", value:"2020-A-0324");
  script_xref(name:"IAVA", value:"2021-A-0035-S");
  script_xref(name:"IAVA", value:"2021-A-0196");
  script_xref(name:"IAVA", value:"2021-A-0480");
  script_xref(name:"IAVB", value:"2020-B-0030");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : ipa Multiple Vulnerabilities (NS-SA-2021-0171)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has ipa packages installed that are affected by
multiple vulnerabilities:

  - jQuery before 3.0.0 is vulnerable to Cross-site Scripting (XSS) attacks when a cross-domain Ajax request
    is performed without the dataType option, causing text/javascript responses to be executed.
    (CVE-2015-9251)

  - In Bootstrap 3.x before 3.4.0 and 4.x-beta before 4.0.0-beta.2, XSS is possible in the data-target
    attribute, a different vulnerability than CVE-2018-14041. (CVE-2016-10735)

  - In Bootstrap before 4.1.2, XSS is possible in the collapse data-parent attribute. (CVE-2018-14040)

  - In Bootstrap before 4.1.2, XSS is possible in the data-container property of tooltip. (CVE-2018-14042)

  - In Bootstrap before 3.4.0, XSS is possible in the tooltip data-viewport attribute. (CVE-2018-20676)

  - In Bootstrap before 3.4.0, XSS is possible in the affix configuration target property. (CVE-2018-20677)

  - jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true,
    {}, ...) because of Object.prototype pollution. If an unsanitized source object contained an enumerable
    __proto__ property, it could extend the native Object.prototype. (CVE-2019-11358)

  - In Bootstrap before 3.4.1 and 4.3.x before 4.3.1, XSS is possible in the tooltip or popover data-template
    attribute. (CVE-2019-8331)

  - In jQuery versions greater than or equal to 1.2 and before 3.5.0, passing HTML from untrusted sources -
    even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and
    others) may execute untrusted code. This problem is patched in jQuery 3.5.0. (CVE-2020-11022)

  - A flaw was found in all ipa versions 4.x.x through 4.8.0. When sending a very long password (>= 1,000,000
    characters) to the server, the password hashing process could exhaust memory and CPU leading to a denial
    of service and the website becoming unresponsive. The highest threat from this vulnerability is to system
    availability. (CVE-2020-1722)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0171");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2015-9251");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2016-10735");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-14040");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-14042");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-20676");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-20677");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-11358");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8331");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-11022");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-1722");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL ipa packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11022");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python2-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python2-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python2-ipaserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python2-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python2-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python2-ipaserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'ipa-client-4.6.8-5.el7.centos',
    'ipa-client-common-4.6.8-5.el7.centos',
    'ipa-common-4.6.8-5.el7.centos',
    'ipa-python-compat-4.6.8-5.el7.centos',
    'ipa-server-4.6.8-5.el7.centos',
    'ipa-server-common-4.6.8-5.el7.centos',
    'ipa-server-dns-4.6.8-5.el7.centos',
    'ipa-server-trust-ad-4.6.8-5.el7.centos',
    'python2-ipaclient-4.6.8-5.el7.centos',
    'python2-ipalib-4.6.8-5.el7.centos',
    'python2-ipaserver-4.6.8-5.el7.centos'
  ],
  'CGSL MAIN 5.05': [
    'ipa-client-4.6.8-5.el7.centos',
    'ipa-client-common-4.6.8-5.el7.centos',
    'ipa-common-4.6.8-5.el7.centos',
    'ipa-python-compat-4.6.8-5.el7.centos',
    'ipa-server-4.6.8-5.el7.centos',
    'ipa-server-common-4.6.8-5.el7.centos',
    'ipa-server-dns-4.6.8-5.el7.centos',
    'ipa-server-trust-ad-4.6.8-5.el7.centos',
    'python2-ipaclient-4.6.8-5.el7.centos',
    'python2-ipalib-4.6.8-5.el7.centos',
    'python2-ipaserver-4.6.8-5.el7.centos'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ipa');
}
