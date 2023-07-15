#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135583);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-10086",
    "CVE-2019-12402",
    "CVE-2019-16942",
    "CVE-2019-16943",
    "CVE-2019-17195",
    "CVE-2019-17531"
  );
  script_xref(name:"IAVA", value:"2020-A-0140-S");
  script_xref(name:"IAVA", value:"2021-A-0347-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Primavera Gateway (Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
the following vulnerabilities as referenced in the April 2020 CPU advisory:

  - In Apache Commons Beanutils 1.9.2, a special BeanIntrospector class was added which allows
    suppressing the ability for an attacker to access the classloader via the class property available on all
    Java objects. However, this characteristic of the PropertyUtilsBean was not used by default.
    (CVE-2019-10086)

  - The file name encoding algorithm used internally in Apache Commons Compress 1.15 to 1.18 can get into an
    infinite loop when faced with specially crafted inputs. This can lead to a denial of service attack if an
    attacker can choose the file names inside of an archive created by Compress. (CVE-2019-12402)

  - A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.0.0 through 2.9.10. When Default
    Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and
    the service has the p6spy (3.8.6) jar in the classpath, and an attacker can find an RMI service endpoint
    to access, it is possible to make the service execute a malicious payload. This issue exists because of
    com.p6spy.engine.spy.P6DataSource mishandling. (CVE-2019-16943)

  - Connect2id Nimbus JOSE+JWT before v7.9 can throw various uncaught exceptions while parsing a JWT, which
    could result in an application crash (potential information disclosure) or a potential authentication
    bypass. (CVE-2019-17195)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16943");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_gateway");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_gateway.nbin");
  script_require_keys("installed_sw/Oracle Primavera Gateway");
  script_require_ports("Services/www", 8006);

  exit(0);
}

include('http.inc');
include('vcf.inc');

get_install_count(app_name:'Oracle Primavera Gateway', exit_if_zero:TRUE);

port = get_http_port(default:8006);

app_info = vcf::get_app_info(app:'Oracle Primavera Gateway', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '16.2.0',
    'max_version' : '16.2.11',
    'fixed_display' : 'Upgrade to the latest version or contact customer support for more information.'
  },
  { 'min_version' : '17.12.0', 'fixed_version' : '17.12.7' },
  { 'min_version' : '18.8.0',  'fixed_version' : '18.8.8.9' },
  { 'min_version' : '19.12.0', 'fixed_version' : '19.12.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
