#TRUSTED 3f2508151a5ed0b1551e37a4aae7d8047681921e85174aa62d3075fb91d5686189264d19c43b4909083e1844d6254b19ccacad769e7add2d8000263df2b10e5399457d703b247bbc740dec50574c71e95658672ce787bec10cd5c3c4a48bcba754b3e4852307d7e2b2c91a441028dfed75583589770ac55b0136edea8175d4908f50d157ad3434dec79a8da74f53e8ed55086abeec3e7104f7d83833684a1a1c3069d963ff3b68738280215e13f1ec4de3e9af357a110cdb4d33fae7aa35ef4cf9051cbc5ae92824ab7f925ae6daee2dad4ef6abba111e980d1526121e85aaf8e9d5e8243dc5f6a5d0c5011531087dd1d1a9728e7920c8e6cbb3b799d19106351739567ae85dac4832c7337cd2ce2db42692add6c0cf1fbc608b0c7ae2645e9612db40108181a9b9b215e2b1b5adb864372a8a96214879f3a221bee84d4725b2cc076a9458a7dc938b648febf893b9db13d041a051d9b75036881ff3351c108407683269b417d88feddbc5b9e3093c145486c426d0f4cef2c9e03aa5d7566fe1cf010948a0bb2f5bbcea86d1cc91e1d1c569129514bada9de4992161797d726eed315b271e443ea9cc1094f79c4526b81eec0220587b36c4d408b4aaa9011db62eb69f1c9ab695d434640892d48817d81507ca197f6bcc084770a4a0e15f9ed6b0b2c3b26abc510e2aa0abe0605c4ca8a6641a894d4e13d44aca6335332d7866
#TRUST-RSA-SHA256 90d72c0168d8834a46a1f370b4c5d9a5aa2fca07498a8244cca4e6887bd8c639211b8e2899971dcc3c61094a92d495ed52b24f9aeefbb5d971fe299f754b21039ed655cd8725c28f65c62555eca1e85cdfe5389dcc67056aedb051c9cf4a87af6d6c593ffe8a83709d48c71f7203e27184a1f90cd53e13a85552e5091374ff0a7f113459fe2c4aedd67e34f9ebbf7b1bd428556a32b3ce156a970204a083d7e6b83042c0f4690adf751f91acff1695955e1c536d8ca503c3e56f3cd83bf3f34337478767072d4ddca8a31697405fd18f26b456e160d322f85beb5b7a5c2b36d2f1d0e02614bedaaf913e987cb94fa656cc5c30bf8e05b1cc76227b8471568bf790b594ec5837bf8fabf12321b36773c5d4113086931e75b305f36467117e90e52a9e285d9312b3a58dd41dfb38f2227dc52023c5b405032e2cd87914a7be498fb57f05e5ef2bfaad1d663525c273f9038d6b43158ae430e575f4d4be83a3999c4a3d5c375e84fdbe59fde8483cc4689ada9d5e6be1094dd5d1d3d2f26d04d71269a27b4269fab643c7a9327738eb46ef2eb85e646394eff564e7fdf34b292b4702a15ff67e6a2353c75d8899852fc7c4378b65be00d1231f5deb5067fabdb47c4f66130633db8aa8d757cb2638e29270e55e8c3595879e19303664dce2c6e42b490caac02d9ce3043fe83ed15d135c386b4e9ef1f078fb0fcff52be2c35b0a47
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152410);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3577");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt02409");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-inline-dos-nXqUyEqM");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Firepower Threat Defense Software Inline Pair/Passive Mode DoS (cisco-sa-ftd-inline-dos-nXqUyEqM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a vulnerability in the
ingress packet processing path for interfaces that are configured either as Inline Pair or in Passive mode could allow
an unauthenticated, adjacent attacker to cause a denial of service (DoS) condition. The vulnerability is due to
insufficient validation when Ethernet frames are processed. An attacker could exploit this vulnerability by sending
malicious Ethernet frames through an affected device. A successful exploit could allow the attacker do either of the
following: Fill the /ngfw partition on the device: A full /ngfw partition could result in administrators being unable to
log in to the device (including logging in through the console port) or the device being unable to boot up correctly.
Note: Manual intervention is required to recover from this situation. Customers are advised to contact the Cisco
Technical Assistance Center (TAC) to help recover a device in this condition. Cause a process crash: The process crash
would cause the device to reload. No manual intervention is necessary to recover the device after the reload.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-inline-dos-nXqUyEqM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aac93a08");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt02409");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt02409");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3577");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0',   'fix_ver': '6.3.0.6'},
  {'min_ver': '6.4.0', 'fix_ver': '6.4.0.10'},
  {'min_ver': '6.5.0', 'fix_ver': '6.5.0.5'},
  {'min_ver': '6.6.0', 'fix_ver': '6.6.1'}
];

var is_ftd_cli = get_kb_item("Host/Cisco/Firepower/is_ftd_cli");
var workarounds, workaround_params, extra, cmds;

if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
  else
  {
    workarounds = make_list();
    extra = 'Note that Nessus was unable to check for workarounds';
  }
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['passive_mode'];

  cmds = make_list('show running-config');
}

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt02409',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
