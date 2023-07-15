#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171896);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/06");

  script_cve_id("CVE-2023-20855");
  script_xref(name:"VMSA", value:"2023-0005");
  script_xref(name:"IAVA", value:"2023-A-0113");

  script_name(english:"VMware vCenter / vRealize Orchestrator 8.x < 8.11.1 XXE (VMSA-2023-0005)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application installed that is
affected by an XML external entity vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter / vRealize Orchestrator installed on the remote host is 8.x < 8.11.1. It is, therefore, 
affected by an XML external entity vulnerability. A malicious actor, with non-administrative access to vRealize 
Orchestrator, may be able to use specially crafted input to bypass XML parsing restrictions leading to access to 
sensitive information or possible escalation of privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2023-0005.html");
  script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in VMware KB 2141244.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20855");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_orchestrator");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_orchestrator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vcenter_orchestrator_installed.nbin");
  script_require_keys("installed_sw/VMware vCenter Orchestrator");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'VMware vCenter Orchestrator';
get_install_count(app_name:app, exit_if_zero:TRUE);

var app_info = vcf::get_app_info(app:app);

var constraints = [
  {'min_version':'8.0.0', 'fixed_version':'8.11.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);