#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105785);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id("CVE-2017-4949", "CVE-2017-4950", "CVE-2017-5715");
  script_bugtraq_id(102376, 102489, 102490);
  script_xref(name:"VMSA", value:"2018-0004");
  script_xref(name:"IAVA", value:"2018-A-0020");
  script_xref(name:"VMSA", value:"2018-0005");

  script_name(english:"VMware Workstation 12.x < 12.5.9 / 14.x < 14.1.1 Multiple Vulnerabilities (VMSA-2018-0004) (VMSA-2018-0005) (Spectre)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is
affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote Windows
host is 14.x prior to 14.1.1 or 12.x prior to 12.5.9. It is, therefore,
missing security updates that add hypervisor-assisted guest remediation for a
speculative execution vulnerability (CVE-2017-5715). These updates
will allow guest operating systems to use hardware support for
branch target mitigation and will require guest OS security updates
as detailed in VMware Knowledge Base article 52085.
It is also affected by use-after-free and integer-overflow vulnerabilities.

Note that hypervisor-specific remediation's for this vulnerability
were released as part of VMSA-2018-0002.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/us/security/advisories/VMSA-2018-0004.html");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0005.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/52085");
  script_set_attribute(attribute:"see_also", value:"https://spectreattack.com/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation version 12.5.9 / 14.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4950");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Workstation");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '14.0', 'fixed_version' : '14.1.1'},
  { 'min_version' : '12.0', 'fixed_version' : '12.5.9'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
