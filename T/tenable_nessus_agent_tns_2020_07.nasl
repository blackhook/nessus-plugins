##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142054);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/29");

  script_cve_id("CVE-2020-5793");

  script_name(english:"Tenable Nessus Agent 8.x < 8.1.1 Privilege Escalation Vulnerability (TNS-2020-07)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Nessus Agent installed on the remote Windows host is affected by a privilege escalation 
vulnerability");
  script_set_attribute(attribute:"description", value:
"A vulnerability in Nessus Agent 8.0.0 and 8.1.0 for Windows could allow an authenticated local 
attacker to copy user-supplied files to a specially constructed path in a specifically named user 
directory. An attacker could exploit this vulnerability by creating a malicious file and copying 
the file to a system directory. The attacker needs valid credentials on the Windows system to 
exploit this vulnerability.

Tenable has included a fix in Nessus Agent 8.2.0 and Nessus Agent 8.1.1 to address this issue.
Note that Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2020-07");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus Agent version 8.1.1, 8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5793");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus_agent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_nessus_agent_installed_win.nbin");
  script_require_keys("installed_sw/Tenable Nessus Agent", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Tenable Nessus Agent', win_local:TRUE);

constraints = [
  {'min_version' : '8.0.0', 'fixed_version' : '8.1.1', 'fixed_display': '8.1.1 / 8.2.0'},
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

