##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163939);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2022-31656",
    "CVE-2022-31657",
    "CVE-2022-31658",
    "CVE-2022-31659",
    "CVE-2022-31660",
    "CVE-2022-31661",
    "CVE-2022-31662",
    "CVE-2022-31663",
    "CVE-2022-31664",
    "CVE-2022-31665"
  );
  script_xref(name:"VMSA", value:"2022-0021");
  script_xref(name:"IAVA", value:"2022-A-0303");
  script_xref(name:"CEA-ID", value:"CEA-2022-0027");

  script_name(english:"VMware Workspace One Access / VMware Identity Manager Multiple Vulnerabilities (VMSA-2022-0021)");

  script_set_attribute(attribute:"synopsis", value:
"An identity store broker application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware Workspace One Access (formerly VMware Identity Manager) application running on the remote host is affected
by the following vulnerabilities:

  - An authentication bypass vulnerability affecting local domain users. A malicious actor with network access
    to the UI may be able to obtain administrative access without the need to authenticate. (CVE-2022-31656)

  - A remote code execution vulnerability. A malicious actor with administrator and network access can trigger
    a remote code execution. (CVE-2022-31658)

  - A remote code execution vulnerability. A malicious actor with administrator and network access can trigger
    a remote code execution. (CVE-2022-31659)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0021.html");
  script_set_attribute(attribute:"see_also", value:"https://core.vmware.com/vmsa-2022-0021-questions-answers-faq");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/89096");
  script_set_attribute(attribute:"solution", value:
"Apply the HW-160130 hotfix to VMware Workspace One Access / VMware Identity Manager as per the VMSA-2022-0021 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31656");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VMware Workspace ONE Access CVE-2022-31660');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:identity_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workspace_one_access");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workspace_one_access_web_detect.nbin", "vmware_workspace_one_access_installed.nbin");
  script_require_keys("installed_sw/VMware Workspace ONE Access");

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

var app = 'VMware Workspace ONE Access';

var app_info = vcf::vmware_workspace_one_access::get_app_info(combined:TRUE);

# 3.3.[3456] don't have fixed builds, so audit out unless we are doing a paranoid scan
# Remote detection does not pull hotfixes. Require paranoia
if ((app_info.webapp || app_info.version =~ "3\.3\.[3456]\.")  && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app, app_info.version);

var patch = '160130';

var constraints = [
  { 'min_version':'3.3.4.0.0', 'fixed_version':'3.3.7.0.0', 'fixed_display':'Refer to vendor advisory and apply patch HW-160130.' },

  { 'min_version':'19.03.0.1', 'max_version':'19.03.0.1.99999999', 'fixed_display':'19.03.0.1 with HW-160130' },
  
  { 'min_version':'21.08.0.0.0', 'max_version':'21.08.0.0.99999999', 'fixed_display':'21.08.0.0 with HW-160130' },
  { 'min_version':'21.08.0.1', 'max_version':'21.08.0.1.99999999', 'fixed_display':'21.08.0.1 with HW-160130' }
];

vcf::vmware_workspace_one_access::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, expected_patch:patch);
