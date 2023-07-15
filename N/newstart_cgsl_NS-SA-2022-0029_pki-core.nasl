##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0029. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160757);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2019-10146",
    "CVE-2019-10179",
    "CVE-2019-10221",
    "CVE-2020-1721",
    "CVE-2020-25715",
    "CVE-2021-20179"
  );

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : pki-core Multiple Vulnerabilities (NS-SA-2022-0029)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has pki-core packages installed that are affected
by multiple vulnerabilities:

  - A Reflected Cross Site Scripting flaw was found in all pki-core 10.x.x versions module from the pki-core
    server due to the CA Agent Service not properly sanitizing the certificate request page. An attacker could
    inject a specially crafted value that will be executed on the victim's browser. (CVE-2019-10146)

  - A vulnerability was found in all pki-core 10.x.x versions, where the Key Recovery Authority (KRA) Agent
    Service did not properly sanitize recovery request search page, enabling a Reflected Cross Site Scripting
    (XSS) vulnerability. An attacker could trick an authenticated victim into executing specially crafted
    Javascript code. (CVE-2019-10179)

  - A Reflected Cross Site Scripting vulnerability was found in all pki-core 10.x.x versions, where the pki-ca
    module from the pki-core server. This flaw is caused by missing sanitization of the GET URL parameters. An
    attacker could abuse this flaw to trick an authenticated user into clicking a specially crafted link which
    can execute arbitrary code when viewed in a browser. (CVE-2019-10221)

  - A flaw was found in the Key Recovery Authority (KRA) Agent Service in pki-core 10.10.5 where it did not
    properly sanitize the recovery ID during a key recovery request, enabling a reflected cross-site scripting
    (XSS) vulnerability. An attacker could trick an authenticated victim into executing specially crafted
    Javascript code. (CVE-2020-1721)

  - A flaw was found in pki-core 10.9.0. A specially crafted POST request can be used to reflect a DOM-based
    cross-site scripting (XSS) attack to inject code into the search query form which can get automatically
    executed. The highest threat from this vulnerability is to data integrity. (CVE-2020-25715)

  - A flaw was found in pki-core. An attacker who has successfully compromised a key could use this flaw to
    renew the corresponding certificate over and over again, as long as it is not explicitly revoked. The
    highest threat from this vulnerability is to data confidentiality and integrity. (CVE-2021-20179)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0029");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-10146");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-10179");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-10221");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-1721");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-25715");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-20179");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL pki-core packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20179");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:pki-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:pki-base-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:pki-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:pki-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:pki-kra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:pki-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:pki-symkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:pki-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:pki-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:pki-base-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:pki-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:pki-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:pki-kra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:pki-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:pki-symkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:pki-tools");
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
    'pki-base-10.5.18-12.el7_9',
    'pki-base-java-10.5.18-12.el7_9',
    'pki-ca-10.5.18-12.el7_9',
    'pki-core-debuginfo-10.5.18-12.el7_9',
    'pki-javadoc-10.5.18-12.el7_9',
    'pki-kra-10.5.18-12.el7_9',
    'pki-server-10.5.18-12.el7_9',
    'pki-symkey-10.5.18-12.el7_9',
    'pki-tools-10.5.18-12.el7_9'
  ],
  'CGSL MAIN 5.05': [
    'pki-base-10.5.18-12.el7_9',
    'pki-base-java-10.5.18-12.el7_9',
    'pki-ca-10.5.18-12.el7_9',
    'pki-core-debuginfo-10.5.18-12.el7_9',
    'pki-javadoc-10.5.18-12.el7_9',
    'pki-kra-10.5.18-12.el7_9',
    'pki-server-10.5.18-12.el7_9',
    'pki-symkey-10.5.18-12.el7_9',
    'pki-tools-10.5.18-12.el7_9'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pki-core');
}
