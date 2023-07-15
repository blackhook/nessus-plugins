#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108759);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

  script_cve_id("CVE-2017-1788");
  script_bugtraq_id(103497);

  script_name(english:"IBM WebSphere Application Server 9.0.0.0 < 9.0.0.8 Spoof Attack Vulnerability");
  script_summary(english:"Reads the version number from the SOAP and GIOP services.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a spoof attack
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is
version 9.x.x.x prior to 9.0.0.8. It is, therefore,
affected by an spoof attach vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22012341");
  # https://www.ibm.com/blogs/psirt/ibm-security-bulletin-potential-spoofing-attack-in-websphere-application-server-cve-2017-1788/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b96abfa");
  script_set_attribute(attribute:"solution", value:
"Apply IBM WebSphere Application Server 
9.0 Fix Pack 8. Alternatively, upgrade to the minimal fix pack levels
 required by the interim fix and then apply Interim Fix PI90980.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1788");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "ibm_websphere_application_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}


include('vcf.inc');

app = 'IBM WebSphere Application Server';
fix = 'Interim Fix PI89498';

get_install_count(app_name:app, exit_if_zero:TRUE);
app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  audit(AUDIT_PARANOID);

if ('PI89498' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
 { 'min_version' : '9', 'fixed_version' : '9.0.0.8', 'fixed_display' : '9.0.0.8 (Fix Pack 8) or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
