#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144767);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-8730");
  script_bugtraq_id(71549);

  script_name(english:"IBM HTTP Server 8.5.0.0 <= 8.5.5.4 / 8.0.0.0 <= 8.0.0.10 / 7.0.0.0 <= 7.0.0.35 / 6.1.0.0 <= 6.1.0.47 / 6.0.0.0 <= 6.0.2.43 (521711)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by a vulnerability. The SSL profiles component in
F5 BIG-IP LTM, APM, and ASM 10.0.0 through 10.2.4 and 11.0.0 through 11.5.1, AAM 11.4.0 through 11.5.1, AFM 11.3.0
through 11.5.1, Analytics 11.0.0 through 11.5.1, Edge Gateway, WebAccelerator, and WOM 10.1.0 through 10.2.4 and 11.0.0
through 11.3.0, PEM 11.3.0 through 11.6.0, and PSM 10.0.0 through 10.2.4 and 11.0.0 through 11.4.1 and BIG-IQ Cloud and
Security 4.0.0 through 4.4.0 and Device 4.2.0 through 4.4.0, when using TLS 1.x before TLS 1.2, does not properly check
CBC padding bytes when terminating connections, which makes it easier for man-in-the-middle attackers to obtain
cleartext data via a padding-oracle attack, a variant of CVE-2014-3566 (aka POODLE).  NOTE: the scope of this identifier
is limited to the F5 implementation only. Other vulnerable implementations should receive their own CVE ID, since this
is not a vulnerability within the design of TLS 1.x itself.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/521711");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 8.5.5.5, 8.0.0.11, 7.0.0.37 or later. Alternatively, upgrade to the minimal fix pack
level required by the interim fix and then apply Interim Fix PI34229.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-8730");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/10");
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

# Paranoid due to lack of workaround check
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'IBM HTTP Server (IHS)';

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if ('PI34229' >< app_info['Fixes'] || 'PI31516' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
  { 'min_version' : '8.5.0.0', 'max_version' : '8.5.5.4', 'fixed_display' : '8.5.5.5 or Interim Fix PI34229'},
  { 'min_version' : '8.0.0.0', 'max_version' : '8.0.0.10', 'fixed_display' : '8.0.0.11 or Interim Fix PI34229'},
  { 'min_version' : '7.0.0.0', 'max_version' : '7.0.0.35', 'fixed_display' : '7.0.0.37 or Interim Fix PI34229'},
  { 'min_version' : '6.1.0.0', 'max_version' : '6.1.0.47', 'fixed_display' : 'Interim Fix PI31516'},
  { 'min_version' : '6.0.0.0', 'max_version' : '6.0.2.43', 'fixed_display' : 'Interim Fix PI31516'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
