#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175429);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/15");

  script_cve_id(
    "CVE-2015-5237",
    "CVE-2021-22569",
    "CVE-2021-3516",
    "CVE-2021-3518",
    "CVE-2021-39036",
    "CVE-2021-39036",
    "CVE-2022-21680",
    "CVE-2022-24434",
    "CVE-2022-24728",
    "CVE-2022-24729",
    "CVE-2022-31129",
    "CVE-2022-3171",
    "CVE-2022-32212",
    "CVE-2022-32213",
    "CVE-2022-32214",
    "CVE-2022-32215",
    "CVE-2022-32223",
    "CVE-2022-34165",
    "CVE-2022-35255",
    "CVE-2022-35256",
    "CVE-2022-38900",
    "CVE-2022-39135",
    "CVE-2022-41881",
    "CVE-2022-43548",
    "CVE-2022-45061"
  );
  script_xref(name:"IAVB", value:"2023-B-0032");

  script_name(english:"IBM Cognos Analytics Multiple Vulnerabilities (6986505)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Cognos Analytics installed on the remote host is 11.1.x prior to 11.1.7 Fix Pack 7 or 11.2.x 
prior to 11.2.4 FP1. It is, therefore, affected by multiple vulnerabilities, including the following:

  - GNOME libxml2 could allow a remote attacker to execute arbitrary code on the system, caused by a use-after-free 
    flaw in the xmlXIncludeDoProcess() function in xinclude.c. By sending a specially-crafted file, an attacker could 
    exploit this vulnerability to execute arbitrary code on the system. (CVE-2021-3518)

  - Node.js could allow a local attacker to gain elevated privileges on the system, caused by the DLL search order 
    hijacking of providers.dll. By placing a specially crafted file, an attacker could exploit this vulnerability 
    to escalate privileges. (CVE-2022-32223)

  - Node.js marked module is vulnerable to a denial of service, caused by a regular expression denial of service 
    (ReDoS) flaw in inline.reflinkSearch. By sending a specially-crafted regex input, a remote attacker could exploit 
    this vulnerability to cause a denial of service condition. (CVE-2022-21681)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6986505");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Cognos Analytics 11.1.7 FP7, 11.2.4 FP1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3518");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-39135");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:cognos_analytics");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_cognos_analytics_web_detect.nbin");
  script_require_keys("installed_sw/IBM Cognos Analytics");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'IBM Cognos Analytics';

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);


var constraints = [
  { 'min_version':'11.1', 'max_version':'11.1.6', 'fixed_display':'11.1.7 FP7' },
# Remote detection cannot determine fix pack
  { 'equal':'11.1.7', 'fixed_display':'11.1.7 FP7', 'require_paranoia':TRUE },
  { 'min_version':'11.2', 'fixed_version':'11.2.3', 'fixed_display':'11.2.4 FP1'},
# Remote detection cannot determine fix pack
  { 'equal':'11.2.4', 'fixed_display':'11.2.4 FP1', 'require_paranoia':TRUE }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);