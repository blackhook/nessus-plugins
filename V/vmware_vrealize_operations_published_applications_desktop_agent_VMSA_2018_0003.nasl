#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105790);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-4946");
  script_bugtraq_id(102441);
  script_xref(name:"VMSA", value:"2018-0003");
  script_xref(name:"IAVB", value:"2018-B-0011");

  script_name(english:"VMware vRealize Operations for Published Applications Desktop Agent 6.x < 6.5.1 Privilege Escalation Vulnerability (VMSA-2018-0003)");
  script_summary(english:"Looks for VMware VRealize Operations for Published Applications Desktop Agent 6.x installations.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote VVMware vRealize Operations for Publsihed Applications
Desktop Agent (V4PA) 6.x host is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0003.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/52195");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vRealize Operations for Published Applications Desktop
Agent version 6.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4946");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_operations_published_applications_desktop_agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vrealize_operations_published_applications_desktop_agent_installed.nbin");
  script_require_ports("installed_sw/VMware vRealize Operations for Published Applications Desktop Agent");

  exit(0);
}

include("vcf.inc");

app_name = 'VMware vRealize Operations for Published Applications Desktop Agent';

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:app_name, win_local:TRUE);

constraints = [{ "min_version" : "6", "fixed_version" : "6.5.1" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
