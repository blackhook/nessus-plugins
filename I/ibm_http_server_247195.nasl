#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144766);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-0076");
  script_bugtraq_id(66363);

  script_name(english:"IBM HTTP Server 8.0.x < 8.0.0.9 / 8.5.x < 8.5.5.3 (247195)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by a vulnerability. The Montgomery ladder
implementation in OpenSSL through 1.0.0l does not ensure that certain swap operations have a constant-time behavior,
which makes it easier for local users to obtain ECDSA nonces via a FLUSH+RELOAD cache side-channel attack.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/247195");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 8.5.5.3, 8.0.0.9, or later. Alternatively, upgrade to the minimal fix pack levels
 required by the interim fix and then apply Interim Fix PI19700.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0076");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_http_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM HTTP Server (IHS)", "Settings/ParanoidReport");

  exit(0);
}


include('vcf.inc');

# Unable to check for the vulnerable configuration.
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'IBM HTTP Server (IHS)';
fix = 'Interim Fix PI19700';

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if ('PI19700' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
 { 'min_version' : '8.0.0.0', 'max_version' : '8.0.0.8', 'fixed_display' : '8.0.0.9 or ' + fix },
 { 'min_version' : '8.5.0.0', 'max_version' : '8.5.5.2', 'fixed_display' : '8.5.5.3 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
