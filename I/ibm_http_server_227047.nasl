#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144708);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-1896");
  script_bugtraq_id(61129);

  script_name(english:"IBM HTTP Server 8.5.0.0 <= 8.5.5.0 / 8.0.0.0 <= 8.0.0.6 / 7.0.0.0 <= 7.0.0.29 / 6.1.0.0 <= 6.1.0.45 (227047)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by a vulnerability. mod_dav.c in the Apache HTTP
Server before 2.2.25 does not properly determine whether DAV is enabled for a URI, which allows remote attackers to
cause a denial of service (segmentation fault) via a MERGE request in which the URI is configured for handling by the
mod_dav_svn module, but a certain href attribute in XML data refers to a non-DAV URI.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/227047");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 8.5.5.1, 8.0.0.7, 7.0.0.31, 6.1.0.47 or later. Alternatively, upgrade to the minimal
fix pack level required by the interim fix and then apply Interim Fix PM89996.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1896");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/04");

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

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'IBM HTTP Server (IHS)';

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if ('PM89996' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
  { 'min_version' : '8.5.0.0', 'max_version' : '8.5.5.0', 'fixed_display' : '8.5.5.1 or Interim Fix PM89996'},
  { 'min_version' : '8.0.0.0', 'max_version' : '8.0.0.6', 'fixed_display' : '8.0.0.7 or Interim Fix PM89996'},
  { 'min_version' : '7.0.0.0', 'max_version' : '7.0.0.29', 'fixed_display' : '7.0.0.31 or Interim Fix PM89996'},
  { 'min_version' : '6.1.0.0', 'max_version' : '6.1.0.45', 'fixed_display' : '6.1.0.47 or Interim Fix PM89996'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
