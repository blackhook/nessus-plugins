#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144075);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-12613");
  script_bugtraq_id(101560);

  script_name(english:"IBM HTTP Server 7.0.0.0 < 7.0.0.45 / 8.0.0.0 < 8.0.0.15 / 8.5.0.0 < 8.5.5.14 / 9.0.0.0 < 9.0.0.7 Information Disclosure (304539)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by an information disclosure vulnerability. When
apr_time_exp*() or apr_os_exp_time*() functions are invoked with an invalid month field value in Apache Portable Runtime
APR 1.6.2 and prior, out of bounds memory may be accessed in converting this value to an apr_time_exp_t value,
potentially revealing the contents of a different static heap value or resulting in program termination, and may
represent an information disclosure or denial of service vulnerability to applications which call these APR functions
with unvalidated external input.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/304539");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 7.0.0.45, 8.0.0.15, 8.5.5.14, 9.0.0.7, or later. Alternatively, upgrade to the
minimal fix pack levels required by the interim fix and then apply Interim Fix PI90598.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12613");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/10");

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
fix = 'Interim Fix PI90598';

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if ('PI90598' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
 { 'min_version' : '7.0.0.0', 'max_version' : '7.0.0.43', 'fixed_display' : '7.0.0.45 or ' + fix },
 { 'min_version' : '8.0.0.0', 'max_version' : '8.0.0.14', 'fixed_display' : '8.0.0.15 or ' + fix },
 { 'min_version' : '8.5.0.0', 'max_version' : '8.5.5.13', 'fixed_display' : '8.5.5.14 or ' + fix },
 { 'min_version' : '9.0.0.0', 'max_version' : '9.0.0.6', 'fixed_display' : '9.0.0.7 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
