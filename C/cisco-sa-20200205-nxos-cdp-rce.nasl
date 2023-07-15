#TRUSTED 40d60e60194b164398ccac9c3241dab3611c12798d33d648a1540b6e3e4ee4482103566d25025921c974339f9569e31d02b788dcad72e59906c7d06649f8a02f4feb8aba609ff9d89c0a5a78c903e24881bddc30ea5f910896891d6bbc4fbbe86ca0f4e4180f9aca5b7d5ca75e59a71dfc16221e4ac756a8b19bc1e238c0ba1b6eca900fd014cefaed9db19ac4060b9d3aeb2707e2b03b17a3e37f8bab6d7dcbb836530470ea395d498bd4ced4aaa1097091b123a79a16e1c8e7dc90a89c659e31f108293f96f33e88df53df199d2f9d7da5c269d462a1870e5ad986a36644f5ec1d7a2fca4f7fec8e6df5499d5233b74a7d0fde17dbeb75b29616d5506164b9c8b19d5d355831ce1469f8c6a1ccd72c4defaaf43a4522dae047324571407897d62e4e35ab0e452004e83692f69cb30eead7874e98be1b7c45dd13cdfc544b38e0083f9e552e796c6aa57d8c275df73140031cc2381b9312c4ca60af47df08f9713f47836e82ad94dc0a9955fed03fb4d5993e096c023aac23d70d6cc1637a2c367110f0cc73f17127a5252009c51f75a8ce6a9ae0e5939b177beef6e37b947ef407016f1053e324e65aff3dbafbdfc66144484f083e4af1985237637be54e4dc2800a71bcf81f8a3b8eb3a77ae88ed474f8bb2c09c569d202649563e259f3064154e10c3081249ed878bdf4401c832ff7076b83edd0e9962f0d83973a945a67
#TRUST-RSA-SHA256 48d876bbacfd836667582985cef665a29d915ed27f2d11f1a162497dc77abac87871b2bf4fa2bed2d4617dd1f4bd2546f3de7225e7714172f4e2d28071333b2824e9a973e5a0aa366253d6ea474b52537c50d44777a7731951292499089f58c1f17c51aeec8eee36315f7057a69d3411c0e2eec9a64874a0f9df4ffe7bee39b90edacded1defefd1ef47428881566817d1d962a83fb4fc88a53bd59e38a53d2139f32a831a7f10c16efe4c75db5d81c119e6a63adb3d15bd4a19bb322652438e77ae8ffe8da16a83d85babcd63ba6b959e8dee6d7c50e982803b954f1fd7614479f9de30a738c948d1ce54823186fd11e201284b9b69cb3d8d1ea910e2698f6cbc88cf9eafd7bef367c7afa29c3f023dc3c997663aaf6b11af11fc40bf1285e7c3f3937f2ac228d0e7d069f2dbad0f9c5647d9bd2c8a67aa08f4b0f369b8dc0f96627402b544d9744a5702cc5993219da05eb8ad3bf0d0164573549e86e24d89165fd395567675905dbf4abd3f258689a80d543c51d2ecf7228cb41014fdb251e51258ee26b97d3e632bb0025ada78139f0b37d431f6361144e2fb7833e0ac3af528b06a63556db907886b718c4a4ecdc86e0b7713ddc72232fa94c5c092312e5fc9a384cd2c29497ecc460a8da0ef9ef949945524263ccc0540f39f5a7de0803b9f1f3717c5192bc5fa134fa28363d82d5675854332fc431e505cbd051a1ce9
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133604);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-3119");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr09175");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr09531");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200205-nxos-cdp-rce");
  script_xref(name:"IAVA", value:"2020-A-0068");
  script_xref(name:"CEA-ID", value:"CEA-2020-0016");

  script_name(english:"Cisco NX-OS Software Cisco Discovery Protocol Remote Code Execution Vulnerability (cisco-sa-20200205-nxos-cdp-rce)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS System Software is affected by a remote code execution
vulnerability within the Cisco Discovery Protocol due to improper validation of input. An unauthenticated, adjacent
attacker can exploit this to bypass authentication and execute arbitrary commands with root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200205-nxos-cdp-rce
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9811503b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr09175");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr09531");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr09175 and/or CSCvr09531.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3119");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');



cbi = '';

if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ "^3[0-9]{3}")
    cbi = 'CSCvr09175';
  else if (product_info.model =~ "^9[0-9]{3}")
    cbi = 'CSCvr09175, CSCvr09531';
}
if (empty_or_null(cbi))
  audit(AUDIT_HOST_NOT, 'an affected model');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

version_list=make_list(
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)I7(4)',
  '7.0(3)I7(5)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(3z)',
  '7.0(3)I7(6)',
  '7.0(3)I7(6z)',
  '7.0(3)I7(7)',
  '7.0(3)IA7(1)',
  '7.0(3)IA7(2)',
  '7.0(3)IM7(2)',
  '9.2(1)',
  '9.2(2)',
  '9.2(2t)',
  '9.2(3)',
  '9.2(3y)',
  '9.2(4)',
  '9.2(2v)',
  '9.3(1)',
  '9.3(1z)',
  '14.0(1h)',
  '14.0(2c)',
  '14.0(3d)',
  '14.0(3c)',
  '14.1(1i)',
  '14.1(1j)',
  '14.1(1k)',
  '14.1(1l)',
  '14.1(2g)',
  '14.1(2m)',
  '14.1(2o)',
  '14.1(2s)',
  '14.1(2u)',
  '14.1(2w)',
  '14.2(1i)'
);

workarounds = make_list(CISCO_WORKAROUNDS['cdp']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info.version,
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE
);

