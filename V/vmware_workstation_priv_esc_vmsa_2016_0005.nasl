#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91227);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id("CVE-2016-2077");
  script_bugtraq_id(90706);
  script_xref(name:"VMSA", value:"2016-0005");

  script_name(english:"VMware Workstation 11.x < 11.1.3 Host Privilege Escalation (VMSA-2016-0005)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote host is affected
by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is 11.x
prior to 11.1.3. It is, therefore, affected by a privilege escalation
vulnerability due to an improperly referenced executable. A local
attacker can exploit this to gain elevated permissions on the host
system.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0005.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation version 11.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2077");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "VMware/Workstation/Version", "VMware/Workstation/Path");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '11.0', 'fixed_version' : '11.1.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
