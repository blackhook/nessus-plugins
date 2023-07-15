#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58794);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id("CVE-2012-1518");
  script_bugtraq_id(53006);
  script_xref(name:"VMSA", value:"2012-0007");

  script_name(english:"VMware Products Local Privilege Escalation (VMSA-2012-0007)");
  script_summary(english:"Checks vulnerable versions of VMware products");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application affected by a local
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The VMware Workstation installation detected on the remote host is
8.x earlier than 8.0.2 and thus is potentially affected by a local 
privilege escalation vulnerability because the access control list of
the VMware Tools folder is incorrectly set.

By exploiting this issue, a local attacker could elevate his privileges
on Windows-based Guest Operating Systems.");

  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0007.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000172.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation 8.0.2 or later.

In addition to patching, VMware Tools must be updated on all non-
Windows guest VMs in order to completely mitigate the
vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1518");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2023 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "VMware/Workstation/Version");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.0.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
