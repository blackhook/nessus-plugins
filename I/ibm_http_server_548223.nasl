#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144302);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/08");

  script_cve_id("CVE-2016-5387");
  script_bugtraq_id(91816);

  script_name(english:"IBM HTTP Server 7.0.0.0 < 7.0.0.43 / 8.0.0.0 < 8.0.0.13 / 8.5.0.0 < 8.5.5.11 / 9.0.0.0 < 9.0.0.1 HTTP Redirect (548223)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an HTTP redirect vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by an HTTP redirect vulnerability related to
Apache HTTP Server. The Apache HTTP Server through 2.4.23 follows RFC 3875 section 4.1.18 and therefore does not protect
applications from the presence of untrusted client data in the HTTP_PROXY environment variable, which might allow remote
attackers to redirect an application's outbound HTTP traffic to an arbitrary proxy server via a crafted Proxy header in
an HTTP request, aka an 'httpoxy' issue. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/548223");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 7.0.0.43, 8.0.0.13, 8.5.5.11, 9.0.0.1, or later. Alternatively, upgrade to the
minimal fix pack levels required by the interim fix and then apply Interim Fix PI73984.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5387");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/16");

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

# paranoid for config check
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'IBM HTTP Server (IHS)';
fix = 'Interim Fix PI73984';

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if ('PI73984' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
 { 'min_version' : '7.0.0.0', 'max_version' : '7.0.0.41', 'fixed_display' : '7.0.0.43 or ' + fix },
 { 'min_version' : '8.0.0.0', 'max_version' : '8.0.0.12', 'fixed_display' : '8.0.0.13 or ' + fix },
 { 'min_version' : '8.5.0.0', 'max_version' : '8.5.5.10', 'fixed_display' : '8.5.5.11 or ' + fix },
 { 'min_version' : '9.0.0.0', 'max_version' : '9.0.0.0', 'fixed_display' : '9.0.0.1 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
