#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166606);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/05");

  script_cve_id(
    "CVE-2021-3711",
    "CVE-2021-3712",
    "CVE-2021-3733",
    "CVE-2021-3737",
    "CVE-2021-4160",
    "CVE-2021-29425",
    "CVE-2021-43138",
    "CVE-2022-0391",
    "CVE-2022-24758",
    "CVE-2022-34339"
  );
  script_xref(name:"IAVB", value:"2022-B-0041-S");

  script_name(english:"IBM Cognos Analytics Multiple Vulnerabilities (6828527)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Cognos Analytics installed on the remote host is affected by multiple vulnerabilities, including the
following:

  - OpenSSL is vulnerable to a buffer overflow, caused by improper bounds checking by the EVP_PKEY_decrypt()
    function within implementation of the SM2 decryption. By sending specially crafted SM2 content, a remote
    attacker could overflow a buffer and execute arbitrary code on the system or cause the application to
    crash. (CVE-2021-3711)

  - Async could allow a remote attacker to execute arbitrary code on the system, caused by prototype pollution
    in the mapValues() method. By persuading a victim to open a specially-crafted file, an attacker could
    exploit this vulnerability to execute arbitrary code on the system.
    (CVE-2021-43138)

  - Apache Commons IO could allow a remote attacker to traverse directories on the system, caused by improper
    input validation by the FileNameUtils.normalize method. An attacker could send a specially-crafted URL
    request containing 'dot dot' sequences (/../) to view arbitrary files on the system.
    (CVE-2021-29425)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6828527");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Cognos Analytics 11.1.7 FP6, 11.2.3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3711");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:cognos_analytics");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_cognos_analytics_web_detect.nbin");
  script_require_keys("installed_sw/IBM Cognos Analytics");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'IBM Cognos Analytics';

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

# Remote detection cannot determine fix pack
if (app_info.version =~ "^11\.1\.7($|[^0-9])" && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app_info['version'], app);

var constraints = [
  { 'min_version':'11.1', 'fixed_version':'11.1.8', 'fixed_display':'11.1.7 FP6' },
  { 'min_version':'11.2', 'fixed_version':'11.2.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
