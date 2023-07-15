##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161609);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/05");

  script_cve_id("CVE-2022-27183");
  script_xref(name:"IAVA", value:"2022-A-0219-S");

  script_name(english:"Splunk Enterprise 8.1 < 8.1.4 XSS");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host may be affected by a cross-site scripting (XSS) vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Splunk running on the remote web server is Splunk
Enterprise 8.1.x prior to 8.1.4 It may, therefore, be affected by a reflected XSS vulnerability. The Monitoring Console
app configured in Distributed mode allows for a Reflected XSS in a query parameter in Splunk Enterprise versions before 
8.1.4.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.splunk.com/en_us/product-security/announcements/svd-2022-0505.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c05e982e");
  script_set_attribute(attribute:"solution", value:
"Upgrade Splunk Enterprise to version 8.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "macos_splunk_installed.nbin");
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include('vcf.inc');

var app = 'Splunk';

var app_info = vcf::combined_get_app_info(app:app);

# Only 8.1.0 - 8.1.3 can be vulnerable - audit out definitively if it's not these versions before checking for paranoia
if (app_info['version'] !~ "^8\.1\.[0-3]([^0-9]|$)")
  vcf::audit(app_info);

# Not checking the license
if (report_paranoia < 2) audit(AUDIT_POTENTIAL_VULN, app);

var constraints = [
  { 'min_version' : '8.1.0', 'fixed_version' : '8.1.4', 'fixed_display':'8.1.4 / 8.2.0' }
];

vcf::check_version_and_report(app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING, 
  flags:{'xss':TRUE}
);
