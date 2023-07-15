#TRUSTED 24a0d42401f7a306c43545c0eaa7f7089c12f3bd0562bf8b3b50e60e33d0608ce8cdf31f6a4eb8af2c077ac2ca1fbd2fbd9bcb751327b7acdbd55cec9e4195ec1ed7597231b4bf07ba33031787aa8e0d1e3b216830ca4daed2e2406bcffdac1ed3fe2e2db84f4d513370cd6a7b20f8cdce3cd10c44051c56cf4c86cef410d05cb4fd77a1ae339b14a03d2f41c8ad739b17d2145b2b2ad16b4062db44b5d50e331031bf4275bd20475925bfcff21b68db31ee2051badee09f103731f9b0e67db287eca1e32ef3dd2c464dcd786256d6576cd693b394a0e7a043eeb28b48592fd66795fc0d076fbb9dde6145bb61046af95cd723b7bd1790404f8f3f155e783b436641c47b29dc1ac76b5ee18f94356e9b2a071a639a13cbff75d46005e0743855fdceb46c815fa34653389668493cf99c452200e64f00f3a43d82789ccc89f57cded7d047376367152ec43b8c7608bbb0a78cc9923f3a0baaa15a861e98b091c85343b4197cd1fa4919e9f57ca9d38701fbc8ee81eca9a9d70549d8030450cbd9e0a70c7fcc93186b659f4f36ac4cf34777d75ef74391a512d253ecf692d4c3ec3ac0107ca88b8edd4f5fc741939775f9867ab9c09dea113ac0d84be06d5672246b30b73c0d7aab08e3311923c11eed737b96e80fa1de6518689aa9370d7578ef53accb94c0f380445e3ab2c3ab795c460e9d899a7ccb186379dfe26243de7d2b
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142592);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/10");

  script_cve_id("CVE-2020-3284");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi82550");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq23340");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq31064");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu31574");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-pxe-unsign-code-exec-qAa78fD2");
  script_xref(name:"IAVA", value:"2020-A-0503-S");

  script_name(english:"Cisco IOS XR RCE (cisco-sa-iosxr-pxe-unsign-code-exec-qAa78fD2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XR is affected by a remote code execution vulnerability in the 
enhanced Preboot eXecution Environment (PXE) boot loader due to a failure to verify commands issued during a 
network boot. An unauthenticated, remote attacker can exploit this to execute unsigned code on an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-pxe-unsign-code-exec-qAa78fD2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcce002a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi82550");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq23340");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq31064");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu31574");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi82550, CSCvq23340, CSCvq31064, CSCvu31574");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3284");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

# Infeasible to implement required workarounds in a deterministic manner.
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

model = tolower(product_info['model']);

if (model =~ "asr9")
{
  vuln_ranges = [{'min_ver':'0.0', 'fix_ver':'6.5.2'}];
}
else if (model =~ "ncs10[0-9]{2}")
{
  vuln_ranges = [{'min_ver':'0.0', 'fix_ver':'7.1.1'}];
}
else if (model =~ "ncs540")
{
  vuln_ranges = [{'min_ver':'0.0', 'fix_ver':'7.2.1'}];
}
else if (model =~ "ncs560")
{
  # 6.6.3, 6.6.25 & 7.0.2 are listed as fix versions.
  # https://software.cisco.com/download/home/286318884/type/280805694/release/6.6.25?i=!pp
  # Doesn't seem to be any releases between 6.6.3 & 6.6.25
  vuln_ranges = [
    {'min_ver':'0.0', 'fix_ver':'6.6.3'},
    {'min_ver':'7.0', 'fix_ver':'7.0.2'}
  ];
}
else if (model =~ "ncs50[0-9]{2}")
{
  vuln_ranges = [{'min_ver':'0.0', 'fix_ver':'7.2.1'}];
}
else if (model =~ "ncs55[0-9]{2}")
{
  # 6.6.3 & 6.6.25 are listed as fix versions.
  # https://software.cisco.com/download/home/286313213/type/280805694/release/6.6.3
  # Doesn't seem to be any releases between 6.6.3 & 6.6.25
  vuln_ranges = [
    {'min_ver':'0.0', 'fix_ver':'6.6.3'}
  ];
}
else
{
  audit(AUDIT_HOST_NOT, 'an affected model');
}

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi82550, CSCvq23340, CSCvq31064, CSCvu31574',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
