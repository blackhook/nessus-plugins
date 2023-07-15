#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(64921);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id("CVE-2013-1406");
  script_bugtraq_id(57867);
  script_xref(name:"VMSA", value:"2013-0002");

  script_name(english:"VMware Workstation 8.x < 8.0.5 / 9.x < 9.0.1 VMCI Privilege Escalation (VMSA-2013-0002)");
  script_summary(english:"Checks versions of VMware Workstation");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a virtualization application that is affected by a
privilege escalation vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VMware Workstation installed on the remote host is a
version prior to 8.0.5 / 9.0.1.  It is, therefore, reportedly affected
by a privilege escalation vulnerability in the Virtual Machine
Communication Interface (VMCI) in the 'VMCI.sys' driver. 

By exploiting this issue, a local attacker could elevate their
privileges on Windows-based hosts or Windows-based Guest Operating
Systems. 

Note that systems that have VMCI disabled are also affected by this
issue."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Workstation 8.0.5 / 9.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1406");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("VMware/Workstation/Version", "VMware/Workstation/Path");
  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.0.5'},
  { 'min_version' : '9.0', 'fixed_version' : '9.0.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
