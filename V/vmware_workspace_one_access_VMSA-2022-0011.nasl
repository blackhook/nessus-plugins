#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159548);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id(
    "CVE-2022-22954",
    "CVE-2022-22955",
    "CVE-2022-22956",
    "CVE-2022-22957",
    "CVE-2022-22958",
    "CVE-2022-22959",
    "CVE-2022-22960",
    "CVE-2022-22961"
  );
  script_xref(name:"VMSA", value:"2022-0011");
  script_xref(name:"IAVA", value:"2022-A-0136-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/05");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/06");
  script_xref(name:"CEA-ID", value:"CEA-2022-0012");

  script_name(english:"VMware Workspace One Access / VMware Identity Manager Multiple Vulnerabilities (VMSA-2022-0011)");

  script_set_attribute(attribute:"synopsis", value:
"An identity store broker application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware Workspace One Access (formerly VMware Identity Manager) application running on the remote host is affected
by the following vulnerabilities:

  - Server-side Template Injection Remote Code Execution Vulnerability (CVE-2022-22954)
  - OAuth2 ACS Authentication Bypass Vulnerabilities (CVE-2022-22955, CVE-2022-22956)
  - JDBC Injection Remote Code Execution Vulnerabilities (CVE-2022-22957, CVE-2022-22958)
  - Cross Site Request Forgery Vulnerability (CVE-2022-22959)
  - Local Privilege Escalation Vulnerability (CVE-2022-22960)
  - Information Disclosure Vulnerability (CVE-2022-22961)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0011.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/88099");
  script_set_attribute(attribute:"solution", value:
"Apply the HW-154129 hotfix to VMware Workspace One Access / VMware Identity Manager as per the VMSA-2022-0011 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22954");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-22956");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VMware Workspace ONE Access CVE-2022-22954');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workspace_one_access");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:identity_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workspace_one_access_web_detect.nbin");
  script_require_keys("installed_sw/VMware Workspace ONE Access");

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

var app = 'VMware Workspace ONE Access';

get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:80);

var app_info = vcf::vmware_workspace_one_access::get_app_info(port:port);

# 3.3.[3456] don't have fixed builds, so audit out unless we are doing a paranoid scan
if (app_info.version =~ "3\.3\.[3456]\."  && report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  { 'min_version':'3.3.3.0.0', 'fixed_version':'3.3.4.0.0', 'fixed_display':'3.3.3 with HW-154129' },
  { 'min_version':'3.3.4.0.0', 'fixed_version':'3.3.5.0.0', 'fixed_display':'3.3.4 with HW-154129' },
  { 'min_version':'3.3.5.0.0', 'fixed_version':'3.3.6.0.0', 'fixed_display':'3.3.5 with HW-154129' },
  { 'min_version':'3.3.6.0.0', 'fixed_version':'3.3.7.0.0', 'fixed_display':'3.3.6 with HW-154129' },

  { 'min_version':'20.10.0.0', 'fixed_version':'20.10.0.0.19540061', 'fixed_display':'20.10.0.0 Build 19540061 (HW-154129)' },
  { 'min_version':'20.10.0.1', 'fixed_version':'20.10.0.1.19540061', 'fixed_display':'20.10.0.1 Build 19540061 (HW-154129)' },
  { 'min_version':'21.08.0.0', 'fixed_version':'21.08.0.0.19539711', 'fixed_display':'21.08.0.0 Build 19539711 (HW-154129)' },
  { 'min_version':'21.08.0.1', 'fixed_version':'21.08.0.1.19539711', 'fixed_display':'21.08.0.1 Build 19539711 (HW-154129)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
