##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163434);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2021-31559");
  script_xref(name:"IAVA", value:"2022-A-0251-S");

  script_name(english:"Splunk Enterprise 8.1.x < 8.1.5, 8.2.x < 8.2.1 Authentication Bypass");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host may be affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"A crafted request bypasses S2S TCP Token authentication writing arbitrary events to an index in Splunk Enterprise 
Indexer 8.1 versions before 8.1.5 and 8.2 versions before 8.2.1. The vulnerability impacts Indexers configured to use 
TCPTokens. It does not impact Universal Forwarders.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.splunk.com/en_us/product-security/announcements/svd-2022-0503.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9136360");
  script_set_attribute(attribute:"solution", value:
"Upgrade Splunk Enterprise to version 8.1.5, 8.2.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31559");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "macos_splunk_installed.nbin");
  script_require_keys("installed_sw/Splunk");
  script_require_ports("Services/www", 8089);

  exit(0);
}

include('vcf.inc');

var app = 'Splunk';

var app_info = vcf::combined_get_app_info(app:app);

# Only 8.1 and 8.2 can be vulnerable - audit out definitively if it's not this version before checking for paranoia
if (app_info['version'] !~ "^8\.[12]([^0-9]|$)")
  audit(AUDIT_LISTEN_NOT_VULN, app);

# Not checking license
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app);

var constraints = [
  { 'min_version' : '8.1', 'fixed_version' : '8.1.5' },
  { 'min_version' : '8.2', 'fixed_version' : '8.2.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);