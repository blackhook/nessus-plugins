#TRUSTED 84f5ec6aba905bd7058e494161a3751081e2ed6d470558ae7d0a5812bd07d6069bba035f6a82aada577404d49c7de745f7bdbc4e4e8f27d39f6919de5ec580f12d6417083d4ba332844f33d72e45848ea1bc93d10ea45bc4690ac29071c642bb902a0b9296d5efb09d63fcc9079997b709a0fec8b4c8a663f378de80b3fb4afeefcf65fa60ecb7012336e41654706e686b2d228a80eb5b740e178a78c051d7398704d14eb6b10c00b351289f47daa9c1c5a81facea374e0bf42e9aa8014674ab5e3ed8636a71876ce0b7b441d8ad787a67b3cde984f5e363adcc66db7c0284aac493f92efcd70e00b890d79d7ca9bbe11e57ec1d58d32bf55f4856fa66ab8aea122e2b45bdde3d3700cf911c689f6a744c16af7249536934e5da8c6d3b0213a95e1c8e52b7271c2095f955e2ad4168acb26932b07f47b206e2c10aedac3646366c6007180d6d8538262848db5848cf4ce06f8e49cef1dfb055d19fdaa5fe0d68a76e4e35d6e5c80882bd6f08772910cbfc0d14728e23454cb98ce9d5f4bf9679f6329027b715c146d73dc29b79a81418d9162bb9798e25c735e59edc6ad33d3f0d71d385bc2741e94b33d0322732b4d35552e418d04da54b723f806199bda6ed3f9065b285dea6e0f0aee220305a072ec0eb3a56d21ba5bb3a4ab6bce3d333a5ea20b11e443ea2315d70b2b5e5c8a1c1b6ad74b4bd396fff2d0f4d4c9176455a
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148448);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/23");

  script_cve_id("CVE-2021-1485");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu63474");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xr-cmdinj-vsKGherc");
  script_xref(name:"IAVA", value:"2021-A-0158-S");

  script_name(english:"Cisco IOS XR Software Command Injection (cisco-sa-xr-cmdinj-vsKGherc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a command injection vulnerability.
A vulnerability in the CLI of Cisco IOS XR Software could allow an authenticated, local attacker to inject arbitrary
commands that are executed with root privileges on the underlying Linux operating system (OS) of an affected device.
This vulnerability is due to insufficient input validation of commands that are supplied by the user. An attacker could
exploit this vulnerability by authenticating to a device and submitting crafted input to an affected command. A
successful exploit could allow the attacker to execute commands on the underlying Linux OS with root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xr-cmdinj-vsKGherc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a31be3cb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu63474");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu63474");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1485");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(88);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

#Vuln only applies to 64bit devices but there is no reliable way to determine arch but only IOS XR < 7.x can be 32bit so we audit out if ver is < 7.x and paranoia < 2.
if (product_info.version =~ "^[0-6]\." && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, product_info.name, product_info.version);

var vuln_ranges = [
 {'min_ver': '0', 'fix_ver': '7.3.1'}
];

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvu63474',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
 );

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
