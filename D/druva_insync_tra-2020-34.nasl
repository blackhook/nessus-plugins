#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136927);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/29");

  script_cve_id("CVE-2020-5752");

  script_name(english:"Druva inSync Windows Client < 6.6.4 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"A web application development suite installed on the remote Windows
host is affected by local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Windows Druva inSync Client Service (inSyncCPHwnet64.exe) contains a path 
traversal vulnerability that can be exploited by a local, unauthenticated attacker 
to execute OS commands with SYSTEM privileges. When processing RPC type 5 
requests over TCP port 6064, inSyncCPHwnet64.exe does not properly validate request 
data prior to passing it to the CreateProcessW() function. By sending a crafted RPC 
request, an attacker can elevate privileges to SYSTEM.");
  # https://docs.druva.com/005_inSync_Client/inSync_Client_6.6.0_for_inSync_Cloud/000Release_Details/010_Release_Notes_for_inSync_Client_v6.6.0#inSync_Client_Patch_Update_v6.6.4_for_Windows_OS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da4e741b");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2020-34");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Druva inSync Client 6.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5752");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Druva inSync inSyncCPHwnet64.exe RPC Type 5 Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:druva:insync_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("druva_insync_client_win_installed.nbin");
  script_require_keys("installed_sw/Druva inSync");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");
 
app_info = vcf::get_app_info(app:"Druva inSync");

constraints = [
  { 'min_version' : '6.6.0', 'fixed_version' : '6.6.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

