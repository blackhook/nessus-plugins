#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167270);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/22");

  script_cve_id("CVE-2022-20925", "CVE-2022-20926");
  script_xref(name:"IAVA", value:"2022-A-0486");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb23029");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb23048");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fmc-cmd-inj-Z3B5MY35");

  script_name(english:"Cisco Firepower Management Center Software Command Injection Vulnerabilities (cisco-sa-fmc-cmd-inj-Z3B5MY35)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Firepower Management Center installed on the remote host is prior to tested version. It is,
therefore, affected by insufficient validation of user-supplied parameters for certain API endpoints. An attacker 
could exploit these vulnerabilities by sending crafted input to an affected API endpoint. A successful exploit 
could allow an attacker to execute arbitrary commands on the device with low system privileges.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-cmd-inj-Z3B5MY35
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c6d8b22");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb23029");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb23048");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwb23029, CSCwb23048");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20925");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-20926");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/10");

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

app_info = vcf::get_app_info(
  app:'Cisco Firepower Management Center',
  kb_ver:'Host/Cisco/firepower_mc/version'
);

# Only vuln if device configured to use host input client feature.
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

vcf::check_granularity(app_info:app_info, sig_segments:3);
constraints = [{'fixed_version':'7.2.0'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
