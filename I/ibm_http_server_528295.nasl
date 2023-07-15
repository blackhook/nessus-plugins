#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144090);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-1829");
  script_bugtraq_id(75164);

  script_name(english:"IBM HTTP Server 8.5.0.0 <= 8.5.5.5 / 8.0.0.0 <= 8.0.0.10 / 7.0.0.0 <= 7.0.0.37 / 6.1.0.0 <= 6.1.0.47 / 6.0.0.0 <= 6.0.2.43 (528295)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by a vulnerability. Unspecified vulnerability in
the Oracle HTTP Server component in Oracle Fusion Middleware 10.1.3.5, 11.1.1.7, 11.1.1.9, 12.1.2.0, and 12.1.3.0 allows
remote attackers to affect availability via unknown vectors related to Web Listener.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/528295");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 8.5.5.7, 8.0.0.11, 7.0.0.39 or later. Alternatively, upgrade to the minimal fix pack
level required by the interim fix and then apply Interim Fix PI39833.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1829");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_http_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM HTTP Server (IHS)");

  exit(0);
}

include('vcf.inc');

app = 'IBM HTTP Server (IHS)';
fix = 'Interim Fix PI39833';

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

 if ('PI39833' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
  { 'min_version' : '8.5.0.0', 'max_version' : '8.5.5.5', 'fixed_display' : '8.5.5.7 or Interim Fix PI39833'},
  { 'min_version' : '8.0.0.0', 'max_version' : '8.0.0.10', 'fixed_display' : '8.0.0.11 or Interim Fix PI39833'},
  { 'min_version' : '7.0.0.0', 'max_version' : '7.0.0.37', 'fixed_display' : '7.0.0.39 or Interim Fix PI39833'},
  { 'min_version' : '6.1.0.0', 'max_version' : '6.1.0.47', 'fixed_display' : 'Interim Fix  PI39833'},
  { 'min_version' : '6.0.0.0', 'max_version' : '6.0.2.43', 'fixed_display' : 'Interim Fix  PI39833'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
