#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169582);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/12");

  script_cve_id(
    "CVE-2022-25647",
    "CVE-2022-29469",
    "CVE-2022-36364",
    "CVE-2022-38708",
    "CVE-2022-39160",
    "CVE-2022-42003",
    "CVE-2022-42004",
    "CVE-2022-43883",
    "CVE-2022-43887"
  );
  script_xref(name:"IAVB", value:"2023-B-0001-S");

  script_name(english:"IBM Cognos Analytics Multiple Vulnerabilities (6841801)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Cognos Analytics installed on the remote host is 11.1.x prior to 11.1.7 Fix Pack 6 or 11.2.x prior
to 11.2.4. It is, therefore, affected by multiple vulnerabilities, including the following:

  - A flaw in the JDBC driver of Apache Calcite Avatica can allow an unauthenticated, remote attacker to
    execute arbitrary code on the affected system. (CVE-2022-36364)

  - A server-side request forgery (SSRF) in IBM Cognos Analytics caused by constructing URLs from
    user-controlled data. An unauthenticated remote attacker can exploit this to make arbitrary requests to
    the internal network or local file system. (CVE-2022-38708)

  - Deserialization of untrusted data in Google Gson triggered by an unauthenticated, remote attacker can
    lead to a denial of service. (CVE-2022-25647)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6841801");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Cognos Analytics 11.1.7 FP6, 11.2.4, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25647");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-38708");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/05");

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
  { 'min_version':'11.1', 'max_version':'11.1.6', 'fixed_display':'11.1.7 FP6' },
# Remote detection cannot determine fix pack
  { 'equal':'11.1.7', 'fixed_display':'11.1.7 FP6', 'require_paranoia':TRUE },
  { 'min_version':'11.2', 'fixed_version':'11.2.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
