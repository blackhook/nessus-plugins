#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154928);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/12");

  script_cve_id("CVE-2021-40124");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz67203");
  script_xref(name:"CISCO-SA", value:"cisco-sa-anyconnect-nam-priv-yCsRNUGT");
  script_xref(name:"IAVA", value:"2021-A-0529-S");

  script_name(english:"Cisco AnyConnect Secure Mobility Client Privilege Escalation (cisco-sa-anyconnect-nam-priv-yCsRNUGT)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco AnyConnect Secure Mobility Client installed on the remote host is prior to 4.10.03104. It is, 
therefore, affected by a privilege escalation vulnerability in its Network Access Manager (NAM) module due to 
incorrect privilege assignment to scripts executed before user logon. An authenticated, local attacker can exploit 
this to gain SYSTEM access on an affected host. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-anyconnect-nam-priv-yCsRNUGT
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8288e9ca");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz67203");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz67203");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40124");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "SMB/Registry/Enumerated", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Cisco AnyConnect Secure Mobility Client', win_local:TRUE);

# Specific module needs to be enabled to be vuln which we are not checking.
if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

var constraints = [{'fixed_version': '4.10.03104'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
