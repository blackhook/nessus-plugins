##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0033. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160789);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-21344",
    "CVE-2021-21345",
    "CVE-2021-21346",
    "CVE-2021-21347",
    "CVE-2021-21350"
  );

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : xstream Multiple Vulnerabilities (NS-SA-2022-0033)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has xstream packages installed that are affected
by multiple vulnerabilities:

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker to load and execute arbitrary code from a
    remote host only by manipulating the processed input stream. No user is affected, who followed the
    recommendation to setup XStream's security framework with a whitelist limited to the minimal required
    types. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least
    version 1.4.16. (CVE-2021-21344, CVE-2021-21346, CVE-2021-21347)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker who has sufficient rights to execute commands
    of the host only by manipulating the processed input stream. No user is affected, who followed the
    recommendation to setup XStream's security framework with a whitelist limited to the minimal required
    types. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least
    version 1.4.16. (CVE-2021-21345)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker to execute arbitrary code only by manipulating
    the processed input stream. No user is affected, who followed the recommendation to setup XStream's
    security framework with a whitelist limited to the minimal required types. If you rely on XStream's
    default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21350)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0033");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-21344");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-21345");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-21346");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-21347");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-21350");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL xstream packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21350");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21345");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:xstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:xstream-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:xstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:xstream-javadoc");
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
    'xstream-1.3.1-13.el7_9',
    'xstream-javadoc-1.3.1-13.el7_9'
  ],
  'CGSL MAIN 5.05': [
    'xstream-1.3.1-13.el7_9',
    'xstream-javadoc-1.3.1-13.el7_9'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xstream');
}
