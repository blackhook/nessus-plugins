##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0010. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160809);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2019-14809", "CVE-2019-16276", "CVE-2020-28362");
  script_xref(name:"IAVB", value:"2019-B-0085-S");
  script_xref(name:"IAVB", value:"2020-B-0071-S");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : docker-ce Multiple Vulnerabilities (NS-SA-2022-0010)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has docker-ce packages installed that are affected
by multiple vulnerabilities:

  - net/url in Go before 1.11.13 and 1.12.x before 1.12.8 mishandles malformed hosts in URLs, leading to an
    authorization bypass in some applications. This is related to a Host field with a suffix appearing in
    neither Hostname() nor Port(), and is related to a non-numeric port number. For example, an attacker can
    compose a crafted javascript:// URL that results in a hostname of google.com. (CVE-2019-14809)

  - Go before 1.12.10 and 1.13.x before 1.13.1 allow HTTP Request Smuggling. (CVE-2019-16276)

  - Go before 1.14.12 and 1.15.x before 1.15.4 allows Denial of Service. (CVE-2020-28362)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0010");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-14809");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-16276");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-28362");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL docker-ce packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14809");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:docker-ce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:docker-ce-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:docker-ce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:docker-ce-debuginfo");
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
    'docker-ce-17.03.3-1.el7.2108201013git6da3bf6',
    'docker-ce-debuginfo-17.03.3-1.el7.2108201013git6da3bf6'
  ],
  'CGSL MAIN 5.04': [
    'docker-ce-17.03.3-1.el7.2108201013git6da3bf6',
    'docker-ce-debuginfo-17.03.3-1.el7.2108201013git6da3bf6'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'docker-ce');
}
