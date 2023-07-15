#TRUSTED 5e8a22ccb8a1d3f230fb443ffd57e809df16c67faaebba9fb04b4d576bba539c42f199f760c101529858c0bc041ce019261520a5c6fa101a1813ba5b2009a60b1aed7a23ad7f1b105a9e26e356fadd1430ed0c97072dd043420ba273c4ad682e6ee313dfdf41d208c1ef12b3d77d31e4a5eadbd5a1e65da37de0d68c58993dcb588b7cdd1ced1a7dbff09716e5a1149474a1271a541d0a77bc52687ca5bc180bb9ddcb16372452724fa89a705126551613090a6dbff7b3df4d1381209c2054a869422b3c52e85547aed94d2ed14679c041174fe42564b89e1bb7725bf52582fc4220673c66f33c064c031d97c3d5ccff9bbb161778e9be7f9ccb0ad3d0884ee6797a7e26fb53dd1d1fb867368b6b275123e0da864818396a5b7fe83f840873ad8e107fc421d029b0b1e79c09468b76d5cc75ff5c9c7330b0c9f822472fbc19202d6e55c93c7e467d6f94571ba046612534b943ec2ef99a17e2bb3fb0a07fda64e988c490491db3cef0d2bb3b7a7e7183382db81afd5192da710b93d67d242caeeaf895fccbd2e78156b4d638a5344da6373becd7eaeab9d5d69ef12cae4fa3de17e94eebe8b4968b6a725bdb7804761ed63b5208598c89e92cfc15f7141d54dbbbb5881a46fbf77f2102cf1cd698f4cd0e7ff838651ba51fa88329877dacd0a5cd749ce216319f17385ee847957c263664e6669d7543f911fc8bc5baad7eeb76
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139411);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/31");

  script_cve_id("CVE-2020-3434");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu22424");
  script_xref(name:"CISCO-SA", value:"cisco-sa-anyconnect-dos-feXq4tAV");
  script_xref(name:"IAVA", value:"2020-A-0351-S");

  script_name(english:"Cisco AnyConnect Secure Mobility Client for Windows DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco AnyConnect Secure Mobility Client is affected a vulnerability in the 
interprocess communication (IPC) channel of Cisco AnyConnect Secure Mobility Client for Windows could allow an 
authenticated, local attacker to cause a denial of service (DoS) condition on an affected device. To exploit this 
vulnerability, the attacker would need to have valid credentials on the Windows system. (CVE-2020-3434)

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-anyconnect-dos-feXq4tAV
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3b436d3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu22424");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu22424");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3434");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco AnyConnect Privilege Escalations (CVE-2020-3153 and CVE-2020-3433)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 427);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Cisco AnyConnect Secure Mobility Client', win_local:TRUE);

// up to and including 4.9.00086 is vuln
constraints = [
  { 'max_version' : '4.9.00086', 'fixed_display' : 'Please see advisory' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);