#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137085);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2020-3307");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh20053");
  script_xref(name:"CISCO-SA", value:"cisco-sa-alfo-tHwFDmTE");
  script_xref(name:"IAVA", value:"2020-A-0237-S");

  script_name(english:"Cisco Firepower Management Center Arbitrary Log File Write Vulnerability (cisco-sa-alfo-tHwFDmTE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Management Center is affected by an arbitrary file write 
  vulnerability due to insufficient user input validation. An unauthenticated, remote attacker can exploit this to 
  write arbitrary entries in the application's log file on the remote host. 
  
  Please see the included Cisco BIDs and Cisco Security Advisory for more information.
 
  Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
  version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-alfo-tHwFDmTE
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?554f0a27");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh20053");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvh20053");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3307");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_management_center");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');

constraints = [{'fixed_version': '6.3.0.2'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
