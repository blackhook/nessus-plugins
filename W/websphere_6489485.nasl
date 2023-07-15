#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153587);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/04");

  script_cve_id("CVE-2021-29842");
  script_xref(name:"IAVA", value:"2021-A-0442-S");

  script_name(english:"IBM WebSphere Application Server Information Disclosure (6489485)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of WebSphere Application Server installed on the remote host is affected by an information disclosure
vulnerability that allows a remote user to enumerate usernames due to a difference of responses from valid and invalid
login attempts.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6489485");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Application Server 8.5.5.21, 9.0.5.10, or later. Alternatively, upgrade to the minimal fix pack
levels required by the interim fix and then apply Interim Fix PH38929.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29842");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "ibm_websphere_application_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');

var app = 'IBM WebSphere Application Server';
var app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# Not checking for federated repository configuration, so audit potential vuln if not paranoid
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app_info['version'], app);

if ('PH38929' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

var fix = 'Interim Fix PH38929';
var constraints = [
  {'min_version':'7.0.0.0', 'max_version':'7.0.0.45', 'fixed_display':fix},
  {'min_version':'8.0.0.0', 'max_version':'8.0.0.15', 'fixed_display':fix},
  {'min_version':'8.5.0.0', 'max_version':'8.5.5.20', 'fixed_display':'8.5.5.21 or ' + fix},
  {'min_version':'9.0.0.0', 'max_version':'9.0.5.9', 'fixed_display':'9.0.5.10 or ' + fix}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
