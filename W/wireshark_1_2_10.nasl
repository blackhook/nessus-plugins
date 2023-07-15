#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48213);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2010-2992", "CVE-2010-2993", "CVE-2010-2994", "CVE-2010-2995");
  script_bugtraq_id(42618);
  script_xref(name:"Secunia", value:"40783");

  script_name(english:"Wireshark / Ethereal < 1.0.15 / 1.2.10 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis",value:
"The remote host has an application that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(attribute:"description",value:
"The installed version of Wireshark or Ethereal is potentially
affected by multiple vulnerabilities. 

  - The SigComp Universal Decompressor Virtual Machine could
    potentially overflow a buffer. (Bug 4867)

  - The ANS.1 BER dissector could potentially exhaust the 
    stack memory. (Bug 4984)

  - The GSM A RR dissector is affected by denial of service
    issue. (Bug 4897)

  - The IPMI dissector could get stuck in an infinite loop. 
    (Bug 5053)"
  );
  script_set_attribute(attribute:"see_also",value:"http://www.wireshark.org/security/wnpa-sec-2010-08.html");
  script_set_attribute(attribute:"see_also",value:"http://www.wireshark.org/security/wnpa-sec-2010-07.html");
  script_set_attribute(attribute:"solution",value:"Upgrade to Wireshark version 1.0.15 / 1.2.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/02");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2023 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '0.10.8', 'max_version' : '1.0.14', 'fixed_version' : '1.0.15' },
  { 'min_version' : '1.2.0', 'max_version' : '1.2.9', 'fixed_version' : '1.2.10' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
