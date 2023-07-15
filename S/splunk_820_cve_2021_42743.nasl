##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162528);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2021-42743");
  script_xref(name:"IAVA", value:"2022-A-0251-S");

  script_name(english:"Splunk Enterprise for Windows 8.1.x < 8.1.1 Local Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host may be affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Splunk running on the remote web server is Splunk
Enterprise 8.1.x prior to 8.1.0. It is, therefore, affected by a misconfiguration in the node default path that
allows for local privilege escalation from a lower privileged user to the Splunk user.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.splunk.com/en_us/product-security/announcements/svd-2022-0501.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c9698ef");
  script_set_attribute(attribute:"solution", value:
"Upgrade Splunk Enterprise to version 8.1.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42743");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Splunk", "Host/OS");
  script_require_ports("Services/www", 8089);

  exit(0);
}

include('vcf.inc');

var app = 'Splunk';
var app_info = vcf::combined_get_app_info(app:app);

var os_remote = get_kb_item('Host/OS');
# Make sure it's Windows
if (get_kb_item("SMB/not_windows") || 'Windows' >!< os_remote)
  audit(AUDIT_HOST_NOT, "Windows");

# Only 8.1.0 can be vulnerable - audit out definitively if it's not this version
if (app_info['version'] !~ "^8\.1\.0([^0-9]|$)")
  vcf::audit(app_info);

# Not checking license
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app);

var constraints = [
  { 'min_version' : '8.1', 'fixed_version' : '8.1.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

