#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152872);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-22029");
  script_xref(name:"IAVB", value:"2021-B-0049");

  script_name(english:"VMware Workspace ONE UEM console DoS (VMSA-2021-0017)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a Denial of Service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the install of Workspace ONE UEM console running on the remote host 
is 2001 prior to 20.1.0.33, 2005 prior to 20.5.0.51, 2008 prior to 20.8.0.32, 2011 prior to 20.11.0.30,
2102 prior to 21.2.0.14, or 2105 prior to 21.5.0.2. It is, therefore, affected by Denial of Service (DoS)
vulnerability. A malicious actor with access to /API/system/admins/session could cause an API denial of 
service due to improper rate limiting.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2021-0017.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/85428");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Workspace ONE UEM console version 20.1.0.33, 20.5.0.51, 20.8.0.32, 20.11.0.30, 
21.2.0.14, 21.5.0.2 or later.

As an alternative, Workspace ONE UEM supports multiple types of authentication for APIs. 
The authentication credentials are sent in the 'Authorization' HTTP request header.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22029");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:airwatch");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workspace_one");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

# Do not know if API auth is enabled
if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_install_count(app_name:'AirWatch Console', exit_if_zero:TRUE);
port = get_http_port(default:443);

app_info = vcf::get_app_info(app:'AirWatch Console', port:port, webapp:TRUE);

if (app_info['Product'] != 'Workspace ONE UEM')
  audit(AUDIT_HOST_NOT, 'affected');


constraints = [
  { 'min_version':'20.1.0.0', 'fixed_version':'20.1.0.33'},
  { 'min_version':'20.3.0.0', 'fixed_version':'20.3.0.24'},
  { 'min_version':'20.4.0.0', 'fixed_version':'20.4.0.22'},
  { 'min_version':'20.5.0.0', 'fixed_version':'20.5.0.51'},
  { 'min_version':'20.6.0.0', 'fixed_version':'20.6.0.20'},
  { 'min_version':'20.7.0.0', 'fixed_version':'20.7.0.15'},
  { 'min_version':'20.8.0.0', 'fixed_version':'20.8.0.32'},
  { 'min_version':'20.10.0.0', 'fixed_version':'20.10.0.19'},
  { 'min_version':'20.11.0.0', 'fixed_version':'20.11.0.30'},
  { 'min_version':'21.1.0.0', 'fixed_version':'21.1.0.18'},
  { 'min_version':'21.2.0.0', 'fixed_version':'21.2.0.14'},
  { 'min_version':'21.5.0.0', 'fixed_version':'21.5.0.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
