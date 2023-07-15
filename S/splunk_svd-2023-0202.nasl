#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171550);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/08");

  script_cve_id("CVE-2023-22932");
  script_xref(name:"IAVA", value:"2023-A-0101-S");

  script_name(english:"Splunk Enterprise < 9.0.4 XSS (SVD-2023-0202)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by an XSS vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Splunk installed on the remote host is prior to 9.0.4. It is, therefore, affected by a cross-site
scripting vulnerability where a View allows for XSS through the error message in a Base64-encoded image. The 
vulnerability affects instances with Splunk Web enabled.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://advisory.splunk.com/advisories/SVD-2023-0202
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f33896ef");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Splunk Enterprise 9.0.4, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22932");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl", "macos_splunk_installed.nbin", "splunk_win_installed.nbin");
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include('vcf_extras_splunk.inc');

var app_info = vcf::splunk::get_app_info();

var constraints = [
  { 'min_version' : '9.0.0', 'fixed_version' : '9.0.4', 'license': 'Enterprise' }
];

vcf::splunk::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});

