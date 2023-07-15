#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156361);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-22054");
  script_xref(name:"IAVA", value:"2021-A-0601");

  script_name(english:"VMware Workspace ONE UEM console SSRF (VMSA-2021-0029)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a server-side request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the install of Workspace ONE UEM console running on the remote host is 2008
prior to 20.8.0.36, 2011 prior to 20.11.0.40, 2102 prior to 21.2.0.27, or 2105 prior to 21.5.0.37. It is, therefore,
affected by a server-side request forgery vulnerability. This issue may allow a malicious actor with network access to
UEM to send their requests without authentication and to gain access to sensitive information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2021-0029.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/87167");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Workspace ONE UEM console version 20.8.0.36, 20.11.0.40, 21.2.0.27, 21.5.0.37 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22054");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:airwatch");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workspace_one");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_airwatch_console_detect_www.nbin");
  script_require_keys("installed_sw/AirWatch Console", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

# Cannot tell if workaround is applied
if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_install_count(app_name:'AirWatch Console', exit_if_zero:TRUE);
port = get_http_port(default:443);

app_info = vcf::get_app_info(app:'AirWatch Console', port:port, webapp:TRUE);

if (app_info['Product'] != 'Workspace ONE UEM')
  audit(AUDIT_HOST_NOT, 'affected');


constraints = [
  { 'min_version':'20.8.0.0',   'fixed_version':'20.8.0.36' }, # Note advisory has 20.0.8.36, but release notes state otherwise
  { 'min_version':'20.11.0.0',  'fixed_version':'20.11.0.40'},
  { 'min_version':'21.2.0.0',   'fixed_version':'21.2.0.27' },
  { 'min_version':'21.5.0.0',   'fixed_version':'21.5.0.37' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
