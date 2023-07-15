##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160491);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2022-20743");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa40237");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fmc-security-bypass-JhOd29Gg");
  script_xref(name:"IAVA", value:"2022-A-0184-S");

  script_name(english:"Cisco Firepower Management Center File Upload Security Bypass (cisco-sa-fmc-security-bypass-JhOd29Gg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Firepower Management Center installed on the remote host is affected by a security bypass
vulnerability in the web management interface that allows an authenticated, remote attacker to bypass security
protections and upload malicious files to the affected system. This vulnerability is due to improper validation of files
uploaded to the web management interface of Cisco FMC Software. An attacker could exploit this vulnerability by
uploading a maliciously crafted file to a device running affected software. A successful exploit could allow the
attacker to store malicious files on the device, which they could access later to conduct additional attacks, including
executing arbitrary code on the affected device with root privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-security-bypass-JhOd29Gg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b0675fe");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa40237");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa40237");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20743");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(434);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_management_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');

vcf::check_granularity(app_info:app_info, sig_segments:3);
var constraints = [
  { 'min_version' : '0.0' , 'fixed_version' : '6.4.0.15'},
  { 'min_version' : '6.5' , 'fixed_version' : '6.6.5.2'},
  { 'min_version' : '6.7' , 'fixed_version' : '7.0.2'},
  { 'min_version' : '7.1' , 'fixed_version' : '7.1.0.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
