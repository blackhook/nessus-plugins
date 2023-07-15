#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168876);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/21");

  script_cve_id("CVE-2022-31700", "CVE-2022-31701");
  script_xref(name:"VMSA", value:"2022-0032");
  script_xref(name:"IAVA", value:"2022-A-0513");

  script_name(english:"VMware Workspace One Access / VMware Identity Manager Multiple Vulnerabilities (VMSA-2022-0032)");

  script_set_attribute(attribute:"synopsis", value:
"An identity store broker application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware Workspace One Access (formerly VMware Identity Manager) application running on the remote host is affected
by the following vulnerabilities:

  - An authentication remote code execution vulnerability. A malicious actor with administrator and network access may 
    be able to remotely execute code on the underlying operating system. (CVE-2022-31700)

  - A broken authentication vulnerability. A malicious actor with network access may be able to obtain system 
    information due to an unauthenticated endpoint. Successful exploitation of this issue can lead to targeting 
    victims. (CVE-2022-31701)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0032.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/90399");
  script_set_attribute(attribute:"solution", value:
"Apply the HW-165708 hotfix to VMware Workspace One Access / VMware Identity Manager as per the VMSA-2022-0032 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31700");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/16");

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

# 3.3.6.0.0 don't have fixed builds, so audit out unless we are doing a paranoid scan
# Remote detection does not pull hotfixes. Require paranoia
if ((app_info.webapp || app_info.version =~ "3.3.6.0.")  && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app, app_info.version);

var patch = '165708';

var constraints = [
  { 'min_version':'3.3.6.0.0', 'fixed_version':'3.3.7.0.0', 'fixed_display':'Refer to vendor advisory and apply patch HW-165708.' },
  { 'min_version':'21.08.0.0', 'fixed_version':'22.09.1.0', 'fixed_display':'Refer to vendor advisory and apply patch HW-165708.' },
  { 'min_version':'21.08.0.1', 'fixed_version':'22.09.1.0', 'fixed_display':'Refer to vendor advisory and apply patch HW-165708.' },
  { 'min_version':'22.09.0.0', 'fixed_version':'22.09.1.0', 'fixed_display':'Refer to vendor advisory and apply patch HW-165708.' }
];

vcf::vmware_workspace_one_access::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, expected_patch:patch);
