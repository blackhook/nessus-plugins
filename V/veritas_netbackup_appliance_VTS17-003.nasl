#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104888);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-6399",
    "CVE-2017-6400",
    "CVE-2017-6401",
    "CVE-2017-6402",
    "CVE-2017-6403",
    "CVE-2017-6404",
    "CVE-2017-6405",
    "CVE-2017-6406",
    "CVE-2017-6407",
    "CVE-2017-6408",
    "CVE-2017-6409"
  );
  script_bugtraq_id(
    96484,
    96485,
    96486,
    96488,
    96489,
    96490,
    96491,
    96493,
    96494,
    96500,
    96504
  );

  script_name(english:"Veritas NetBackup Appliance < 2.7.2 / 3.1.0 Multiple Vulnerabilities (VTS17-003)");

  script_set_attribute(attribute:"synopsis", value:
"The remote backup management appliance is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Veritas NetBackup
Appliance is 2.7.x or 3.0.x. It is, therefore, affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/content/support/en_US/security/VTS17-003.html");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/article.000126394");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veritas NetBackup Appliance version 3.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6409");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veritas:netbackup_appliance");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("veritas_netbackup_appliance_web_console_detect.nbin");
  script_require_keys("installed_sw/NetBackup Appliance");

  exit(0);
}

include("vcf.inc");
include("http.inc");

port = get_http_port(default:443);
if(!port) port = 443;

app_info = vcf::get_app_info(app:"NetBackup Appliance", webapp:true, port:port);

constraints = [
  { "min_version" : "2.7", "max_version" : "3.0.1", "fixed_version" : "3.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
