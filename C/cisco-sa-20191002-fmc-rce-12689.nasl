#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(129809);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2019-12689");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh03951");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-fmc-rce-12689");

  script_name(english:"Cisco Firepower Management Center < 6.2.2.2 Remote Code Execution Vulnerability");
  script_summary(english:"Checks version of Cisco Firepower Management Center");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower 
  Management Center is affected by a remote code execution vulnerability in its web interface component due to 
  insufficient validation of user-supplied input. An authenticated, remote attacker can exploit this to bypass 
  authentication and execute arbitrary commands. 

  Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-fmc-rce-12689
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bf49db8");
  # http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-72541
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61c47b6a");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh03951
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0903148e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID 
  CSCvh03951");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12689");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');
vcf::check_version_and_report(
  app_info:app_info,
  constraints:[{'fixed_version':'6.2.2.2'}],
  severity:SECURITY_HOLE
);
