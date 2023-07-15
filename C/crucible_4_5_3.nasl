#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123687);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/30 13:24:46");

  script_cve_id("CVE-2018-5223");
  script_bugtraq_id(103665);

  script_name(english:"Atlassian Crucible for Windows < 4.4.6, 4.5.x < 4.5.3 Remote Code Execution Vulnerability");
  script_summary(english:"Checks the version of Crucible.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian Crucible installed on the remote Windows host is affected by a Remote Code Execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the installation of Atlassian Crucible running on the remote  Windows host is
prior to 4.4.6 or 4.5.x prior to 4.5.3. It is, therefore, affected by a remote command execution vulnerability due to 
improper sanitization of characters in a Mercurial repository URI which may be interpreted as argument parameters on 
the Windows operating system. An authenticated, remote attacker can exploit this to execute arbitrary commands with the
privileges of the user running the server. 

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://confluence.atlassian.com/crucible/fisheye-and-crucible-security-advisory-2018-03-28-946613862.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed9f2030");
  script_set_attribute(attribute:"solution", value:"Upgrade Crucible to 4.4.6 or later. 
    For Crucible version 4.5.x upgrade 4.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5223");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:crucible");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("crucible_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("installed_sw/crucible");
  script_require_ports("Services/www", 8060);

  exit(0);
}

include("http.inc");
include("vcf.inc");
include("audit.inc");

# Vuln only on Windows
os = get_kb_item_or_exit('Host/OS');
if ('Windows' >!< os) audit(AUDIT_OS_NOT, 'Windows', os);

conf = get_kb_item('Host/OS/Confidence');
if ((conf <= 70) && (report_paranoia < 2 )) 
{
  exit(1, 'Can\'t determine the host\'s OS with sufficient confidence and \'show potential false alarms\' is not enabled.');
}

port = get_http_port(default:8060);
app_info = vcf::get_app_info(app:'crucible', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);
constraints = [
  { 'fixed_version' : '4.4.6' }, { 'min_version' : '4.5.0', 'fixed_version' : '4.5.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
