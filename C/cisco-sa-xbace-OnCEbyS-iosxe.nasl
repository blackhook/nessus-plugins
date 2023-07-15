#TRUSTED 66988258fa16064878bac9dcebb465155b5d4f87de53a84fc0ef26a959bfcda31693a8d6323332aa69d7a227f6a76ddae01bf5ab3faa95c2c5f09480cd3eb2e9faf61172ef8b90b2d406d8be93bb08eaea00ddd2642c65c0f28266bf95ab3eeff2c575bc5147a24d26126bca84721f522e9ff470f2cb57e82a934f7547fac6c09b77f7db66e056798952557530ecd6d0c2dd85f42f58fdc1cc18fde7c1239c955127a16060611b8566f039754a0b0c9a84279685fcd74e9b72cb806ca51c6343601c9bdd657254205fd07c4fc89e2d4b36b77cf5d6b77da3f94668037f0f7203846a6f864421395d81694c4e5c8bea574ab1d575ff038721482c922430d179391a2ed0b1e30f2b14b35af7e90b141ea8a0763d11de4373a2cf9ccbf29f224c806213705e9c0666515785f2c77f6c6e795675568d112b42cb492ec185cfe8a8ba02d7db68b31a5931c001a2fb619744849d8beb0e2e50553995829341d1444555ad9041f7725c51c933e23e7e763bf18cf83c21bedd0a80bb27cbb87625fc0bc51807df7a5e6abd047ad07dd1b160bbd194f7aaff4b61911fe292817dd38853b6e8aa14a93f056c89feb57bb1a474d98bbaf73af19cf448f40b648b182a8f5c31fc2089cf987cf22096c74cb80474ef6d32279a5da30c0d665c6eb2765c20c1bd5cb98941ad65104cd7bd0a5657aecc0f6b0c1059aeb38b6fb41738a5c0533284
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141119);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3417");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs58715");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xbace-OnCEbyS");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software Arbitrary Code Execution Vulnerability (cisco-sa-xbace-OnCEbyS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a arbitrary code execution vulnerability,
due to incorrect validations by boot scripts when specific ROM monitor (ROMMON) variables are set. An authenticated,
local attacker could exploit this vulnerability by installing code to a specific directory in the underlying operating
system (OS) and setting a specific ROMMON variable. A successful exploit could allow the attacker to execute persistent
code on the underlying OS. To exploit this vulnerability, the attacker would need access to the root shell on the
device or have physical access to the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xbace-OnCEbyS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?217cd5d2");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs58715");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs58715");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3417");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.1gSP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.2SP',
  '3.18.2aSP',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.4SP',
  '3.18.5SP',
  '3.18.6SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.18.8aSP'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs58715',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
