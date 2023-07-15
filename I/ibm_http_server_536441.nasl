#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144707);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-4947");
  script_bugtraq_id(76658);

  script_name(english:"IBM HTTP Server 6.1.0.0 <= 6.1.0.47 / 7.0.0.0 < 7.0.0.39 / 8.0.0.0 < 8.0.0.12 / 8.5.0.0 < 8.5.5.7 Stack Buffer Overflow (536441)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a stack buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by a stack-based buffer overflow in the
Administration Server in IBM HTTP Server 6.1.0.x through 6.1.0.47, 7.0.0.x before 7.0.0.39, 8.0.0.x before 8.0.0.12, and
8.5.x before 8.5.5.7, as used in WebSphere Application Server and other products, allows remote authenticated users to
execute arbitrary code via unspecified vectors.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/536441");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 7.0.0.39, 8.0.0.12, 8.5.5.7 or later. Alternatively, upgrade to the minimal fix pack
levels required by the interim fix and then apply Interim Fix PI44793.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4947");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/04");

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
fix = 'Interim Fix PI44793';

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if ('PI44793' >< app_info['Fixes'] || 'PI45596' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
 { 'min_version' : '6.1.0.0', 'max_version' : '6.1.0.47', 'fixed_display' : 'Interim Fix PI45596' },
 { 'min_version' : '7.0.0.0', 'max_version' : '7.0.0.37', 'fixed_display' : '7.0.0.39 or ' + fix },
 { 'min_version' : '8.0.0.0', 'max_version' : '8.0.0.11', 'fixed_display' : '8.0.0.12 or ' + fix },
 { 'min_version' : '8.5.0.0', 'max_version' : '8.5.5.6', 'fixed_display' : '8.5.5.7 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
