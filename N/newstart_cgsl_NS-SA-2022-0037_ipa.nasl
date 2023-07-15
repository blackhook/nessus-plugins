##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0037. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160851);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-11023");
  script_xref(name:"IAVB", value:"2020-B-0030");
  script_xref(name:"IAVA", value:"2022-A-0029");
  script_xref(name:"IAVA", value:"2021-A-0194-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : ipa Vulnerability (NS-SA-2022-0037)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has ipa packages installed that are affected by a
vulnerability:

  - In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing <option>
    elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods
    (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.
    (CVE-2020-11023)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0037");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-11023");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL ipa packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ipa-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ipa-debuginfo");
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

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

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
    'ipa-client-4.6.8-5.el7.centos.4',
    'ipa-client-common-4.6.8-5.el7.centos.4',
    'ipa-common-4.6.8-5.el7.centos.4',
    'ipa-debuginfo-4.6.8-5.el7.centos.4',
    'ipa-python-compat-4.6.8-5.el7.centos.4',
    'ipa-server-4.6.8-5.el7.centos.4',
    'ipa-server-common-4.6.8-5.el7.centos.4',
    'ipa-server-dns-4.6.8-5.el7.centos.4',
    'ipa-server-trust-ad-4.6.8-5.el7.centos.4',
    'python2-ipaclient-4.6.8-5.el7.centos.4',
    'python2-ipalib-4.6.8-5.el7.centos.4',
    'python2-ipaserver-4.6.8-5.el7.centos.4'
  ],
  'CGSL MAIN 5.05': [
    'ipa-client-4.6.8-5.el7.centos.4',
    'ipa-client-common-4.6.8-5.el7.centos.4',
    'ipa-common-4.6.8-5.el7.centos.4',
    'ipa-debuginfo-4.6.8-5.el7.centos.4',
    'ipa-python-compat-4.6.8-5.el7.centos.4',
    'ipa-server-4.6.8-5.el7.centos.4',
    'ipa-server-common-4.6.8-5.el7.centos.4',
    'ipa-server-dns-4.6.8-5.el7.centos.4',
    'ipa-server-trust-ad-4.6.8-5.el7.centos.4',
    'python2-ipaclient-4.6.8-5.el7.centos.4',
    'python2-ipalib-4.6.8-5.el7.centos.4',
    'python2-ipaserver-4.6.8-5.el7.centos.4'
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
