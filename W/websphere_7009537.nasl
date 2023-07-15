#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178028);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2023-35890");
  script_xref(name:"IAVA", value:"2023-A-0326");

  script_name(english:"IBM WebSphere Application Server 8.5.5.23 < 8.5.5.24 / 9.0.5.15 < 9.0.5.17 (7007857)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a improper encoding flaw.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is affected by a improper encoding flaw.
IBM WebSphere Application Server 8.5 and 9.0 traditional could provide weaker than expected security, caused
by the improper encoding in a local configuration file.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7007857");
  script_set_attribute(attribute:"solution", value:
"Update to IBM WebSphere Application Server version 8.5.5.23, 9.0.5.17 or later or apply Interim Fix PH54406.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35890");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "ibm_websphere_application_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');

var app = 'IBM WebSphere Application Server';
var fix = 'Interim Fix PH54406';

get_install_count(app_name:app, exit_if_zero:TRUE);
var app_info = vcf::combined_get_app_info(app:app);

if ('PH54406' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

var require_paranoia = FALSE;
# If the detection is only remote, Source will be set, and we should require paranoia for versions with a fix
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown')
    require_paranoia = TRUE;

vcf::check_granularity(app_info:app_info, sig_segments:4);

var constraints = [
 { 'min_version' : '9.0.5.15', 'fixed_version' : '9.0.5.17', 'fixed_display' : '9.0.5.17 or ' + fix },
 { 'equal' : '8.5.5.23', 'fixed_version' : '8.5.5.24', 'fixed_display' : '8.5.5.24 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, require_paranoia:require_paranoia, severity:SECURITY_WARNING);
