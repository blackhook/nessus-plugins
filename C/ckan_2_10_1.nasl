#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176633);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/05");

  script_cve_id("CVE-2023-32321");

  script_name(english:"CKAN < 2.9.9 / 2.10.1 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The version of CKAN installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of CKAN installed on the remote host is prior to 2.9.9 or 2.10 prior to 2.10.1. It is, therefore,
affected by a remote code execution vulnerability. A remote attacker with permissions to create or edit a dataset
can upload a resource with a specially crafted id to write the uploaded file in an arbitrary location. This
can be leveraged to Remote Code Execution via Beaker's insecure pickle loading.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ckan/ckan/security/advisories/GHSA-446m-hmmm-hm8m");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.9.9, 2.10.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32321");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:okfn:ckan");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ckan_web_detect.nbin");
  script_require_keys("installed_sw/CKAN");

  exit(0);
}
include('http.inc');
include('vcf.inc');

var port = get_http_port(default:5000);

var app = 'CKAN';

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '0', 'fixed_version' : '2.9.9' },
  { 'min_version' : '2.10', 'fixed_version' : '2.10.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

