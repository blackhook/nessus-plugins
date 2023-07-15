##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145045);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/14");

  script_cve_id("CVE-2020-4336");
  script_xref(name:"IAVA", value:"2021-A-0011-S");

  script_name(english:"IBM WebSphere eXtreme Scale 8.6.1 < 8.6.1.4 (6397682)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere eXtreme Scale installed on the remote host is prior to 8.6.1.4. It is, therefore, affected
by a vulnerability as referenced in the 6397682 advisory.

  - IBM WebSphere eXtreme Scale 8.6.1 stores sensitive information in URL parameters. This may lead to
    information disclosure if unauthorized parties have access to the URLs via server logs, referrer header or
    browser history. IBM X-Force ID: 177932. (CVE-2020-4336)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6397682");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere eXtreme Scale 8.6.1.4 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4336");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_extreme_scale");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_websphere_extreme_scale_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere eXtreme Scale");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::get_app_info(app:'IBM WebSphere eXtreme Scale');

var components = app_info['Components'];
if ('Liberty Deployment' >!< components)
    audit(AUDIT_NOT_INST, 'IBM WebSphere eXtreme Scale Liberty Deployment');

if (app_info['version'] =~ "^8\.6\.1" && report_paranoia < 2)
    audit(AUDIT_PARANOID);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '8.6.1', 'fixed_version' : '8.6.1.4' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
