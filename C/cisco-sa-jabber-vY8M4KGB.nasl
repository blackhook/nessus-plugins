#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140219);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/18");

  script_cve_id("CVE-2020-3430");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu96368");
  script_xref(name:"CISCO-SA", value:"cisco-sa-jabber-vY8M4KGB");
  script_xref(name:"IAVA", value:"2020-A-0399-S");

  script_name(english:"Cisco Jabber for Windows Protocol Handler Command Injection (cisco-sa-jabber-vY8M4KGB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Jabber for Windows is affected by a Windows Protocol 
Handler Command Injection vulnerability. The vulnerability exists in the web-based user interface 
due to improper handling of input to the application protocol handlers. An unathenticated, remote
attacker can exploit this via a emailed or messaged link to execute arbitrary commands on a targeted 
system with the privileges of the user account.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-jabber-vY8M4KGB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01e7e8d3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu96368");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu96368");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3430");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:jabber");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_jabber_client_installed.nbin");
  script_require_keys("installed_sw/Cisco Jabber for Windows");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Cisco Jabber for Windows', win_local:TRUE);

constraints = [
  {'min_version' : '12.1', 'fixed_version' : '12.1.3'},
  {'min_version' : '12.5', 'fixed_version' : '12.5.2'},
  {'min_version' : '12.6', 'fixed_version' : '12.6.3'},
  {'min_version' : '12.7', 'fixed_version' : '12.7.2'},
  {'min_version' : '12.8', 'fixed_version' : '12.8.3'},
  {'min_version' : '12.9', 'fixed_version' : '12.9.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);



