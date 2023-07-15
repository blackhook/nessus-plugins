#TRUSTED 352140e7c7ec5fad034c258950c36055a6c2384af26280fee6a2f0b4367759039a53b9824cb15f31487da5fc0de3753babc4de1cfb4064066e8fd394638764837e6c185fe6908bb46e70c1268703b9575173cbe069fd8b3df5ff091704e59748679bf645b0ba6721f47c377cd63f61c2c7db2ab78011a15b1eecd3afd65d93531fba965134c0425cd36766a4ceafd9323ab02abe2ab17d94c36b29d5f6b4f85aaafedc4522e4eca9394dfd688f9ff37dd845902d3f0ab795940781d3aa2dcb390b4dc1de60ad5b0df96276a73ecfe0f8c12f0a6a2945e2a3291a1790b8ac998ede53a7722fd3162e9136ec893f70e87d33be9ef95ff5ef4f4db280966c4285edb4fed2d45d0f4b879ecc2835f9c3ab41ecbbc3223115411c99e4cc4fe8795dcc903cbe18aabec637df682e0f4f27f0dd6b7c9f9238ceeda3968ab1f43e718482c7e095ab5c107407ff17389c7552b7a4eba008a40c6dc41c0665c5cdba9b63e6770db4bda5f0d58ba41953d5f73ee0a7f6da6247f6d9560bae56887d11b499b80f8a1c216ee203f7bf670ea5a95c5f108601fc8238f2bb736b2730b57ee391caabcadd89d69e2670fe4e2cbe6b1f6eeb576aff5fbe1d65877b815754a10efe965c91e8f90c0de271c160777801dc0f819ed53319df82f869f959fde3a97d1850f4b3b4ddd48614b9c225e0cacc8a1d3637724eaaa5bef028820a9f0fc14e8a39
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137203);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3207");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq90824");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ngwc-cmdinj-KEwWVWR");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Command Injection (cisco-sa-ngwc-cmdinj-KEwWVWR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a command injection vulnerability due 
  to insufficient input validation of boot options. An authenticated, local attacker (with root privileges) can exploit 
  this, by modifying device boot options, to execute arbitrary commands on an affected device. 
  
  Please see the included Cisco BIDs and Cisco Security Advisory for more information.
  
  Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
  version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ngwc-cmdinj-KEwWVWR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?851db65e");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq90824");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq90824");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/08");

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
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = product_info['model'];
device_model = get_kb_item('Host/Cisco/device_model');

if (('catalyst' >!< tolower(model) && 'cat' >!< device_model) || model !~ "3[68]5[0-9]|9[235][0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

version_list = make_list(
  '16.9.2',
  '16.9.3',
  '16.9.2a',
  '16.9.2s',
  '16.9.3h',
  '16.9.4',
  '16.9.3s',
  '16.9.3a',
  '16.10.1',
  '16.10.1s',
  '16.10.1e',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1s',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1c'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq90824',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
