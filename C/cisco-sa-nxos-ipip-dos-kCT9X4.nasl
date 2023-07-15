#TRUSTED 9cca2b1be5035da5f115389678a3c8eb640098ab6b0101275a388a78c730ae93a9b7113dcc595117150cbfe82a7e408f0babd92675d6ad49228baaa60b612b0f2cb7a365ddb9e5272cf551eba509eb429a2041466411fcb0249f15ee978b2264c8b6f9692651258acd471c057558db7ba143fde12bcff934a42b0225ca55ed2f5143e2313588674993c9aac3dd2d3d40465de5444f618b74cbbe66fc039c02ab5612a74efcdbaf5e29a68fd93896de125e0d3ac4e75da6766f58c3b1c0ef3c76106ffb9a96de8c293673afa02c61eed77637d1b9f46412343b74a90accc943bb4ede27d59c353c8ed54388302eb5c88fc751c98bdaaadd4554a4c29214469a3d28f2d4e2296cadd34b685d2313876fcf92191ffbe0c8a153263a4254b6977d617d626ba85ad6a72901d32a96f885dd49174c1654f7371ff4ad2a5b6ec72648a8a3675a20b19cf044074514566de3283d6e985161aa70483a8e95b9233bf40660d166bb9457f2718e1c5a54707810c8b776eb47b5f10cfb25b7944abb282fb8e28ba03f93ad24e51924570b6e3b4a5c487df76891204a14d0f6f345656b0ba1913cffb1a8ac0ddc278b17a7e54791403dee394664f2c71aa83619f902fa20f802e375431b70fff9db4958117e7f2f076b9e67ec2be81e47985f81cb4b4475feb751c9bf7ae52459d8a2053c22f9ac27845ad8b123f115585fae156bee14c62d02
#TRUST-RSA-SHA256 7d2e85f256f9425e900caff44f3018607f8e03d5287c4dfff14fb4a54e287e765eef9f6ec8935244974e13a8016415a66fce86fed6fe136c6c5cdfa4ea4311173da9a4af2e0785adf4627e662aea8b64821854291014f0185b7d8f3a2779c3b950ba28607a1c3b6894cf9fb01afc18a0f04bca0103f9d6ab659f5f7dc8f2779ae1b2c8c2dbaaf95635a1c844b1528fe33be7f6d2733652621250074166a314f821a4114b7f66c593745ab389cd5d9de43c87292d897aa8aaa6842e326ccb45cf0a3598cdc1dcf134238cf1cea0999800ddd15be92b6e5d6bd9a512370a27045199864f3d58150ddde232d121afb97497ac8cf19a4ec409f0dea90fbb118c7609107c146b4c2bca7ed755ad96905471c160436a179a0c29a47255a1aac412e095a39ddbe4a7124c2d603a0d91cb8f8c99a70579ea2b60a5daf05982af9ebe8f1db49ad9d5bc84b39d72dbf3cacd86ad2aeb5157c8ecc1e3aba83ee919b5c05a4a2e4ad62c70102b55fbfd6753c824e2437fe7f934fa85dfa3abbd15b9565885dccb2b5fa36413cbf09a5444e295c56c1f661a9dcfee10cdc292a371de21edef81acb5cbeb27432f509d28e815a4ea4f022a8605e56d63a0f0c4b17d9b6ec4454dacca84a353d17561214c0b0780c36be59a45912d21565dda1e21e1a4d99ea9b3d695fc373639280646e3f0f6fe5b9a4ef1ccd0c7f18dfc697afc28e646868c31
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137184);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-10136");
  script_xref(name:"CISCO-BUG-ID", value:"CSCun53663");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt66624");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt67738");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt67739");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt67740");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu03158");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu10050");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-ipip-dos-kCT9X4");
  script_xref(name:"IAVA", value:"2020-A-0233");
  script_xref(name:"CEA-ID", value:"CEA-2020-0049");

  script_name(english:"Cisco NX-OS Software Unexpected IP in IP Packet Processing Vulnerability (cisco-sa-nxos-ipip-dos-kCT9X4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software is affected by a denial of service vulnerability in
the network stack due to the affected device unexpectedly decapsulating and processing IP in IP packets that are
destined to a locally configured IP address. An unauthenticated, remote attacker can exploit this issue by sending a
crafted IP in IP packet to an affected device, to bypass certain security boundaries or cause a denial of service
condition on an affected device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-ipip-dos-kCT9X4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f50ed05");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCun53663");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt66624");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt67738");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt67739");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt67740");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu03158");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu10050");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version or apply the workaround referenced in Cisco bug IDs CSCun53663, CSCvt66624,
CSCvt67738, CSCvt67739, CSCvt67740, CSCvu03158 and CSCvu10050 or alternatively apply the workaround mentioned 
in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10136");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';

if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ "^10[0-9][0-9]"){
    cbi = 'CSCvu10050, CSCvt67738';
    version_list = make_list(
      '5.2(1)SK3(1.1)',
      '5.2(1)SK3(2.1)',
      '5.2(1)SK3(2.1a)',
      '5.2(1)SK3(2.2)',
      '5.2(1)SK3(2.2b)',
      '5.2(1)SM1(5.1)',
      '5.2(1)SM1(5.2)',
      '5.2(1)SM1(5.2a)',
      '5.2(1)SM1(5.2b)',
      '5.2(1)SM1(5.2c)',
      '5.2(1)SM3(1.1)',
      '5.2(1)SM3(1.1a)',
      '5.2(1)SM3(1.1b)',
      '5.2(1)SM3(1.1c)',
      '5.2(1)SM3(2.1)',
      '5.2(1)SV3(1.1)',
      '5.2(1)SV3(1.10)',
      '5.2(1)SV3(1.15)',
      '5.2(1)SV3(1.2)',
      '5.2(1)SV3(1.3)',
      '5.2(1)SV3(1.4)',
      '5.2(1)SV3(1.4b)',
      '5.2(1)SV3(1.5a)',
      '5.2(1)SV3(1.5b)',
      '5.2(1)SV3(1.6)',
      '5.2(1)SV3(2.1)',
      '5.2(1)SV3(2.5)',
      '5.2(1)SV3(2.8)',
      '5.2(1)SV3(3.1)',
      '5.2(1)SV3(3.15)',
      '5.2(1)SV3(4.1)',
      '5.2(1)SV3(4.1a)',
      '5.2(1)SV3(4.1b)',
      '5.2(1)SV5(1.1)',
      '5.2(1)SV5(1.2)',
      '5.2(1)SV5(1.3)'
      );
  }

  if (product_info.model =~ "^3[0-9]{3}")
  {
    cbi = 'CSCun53663';
    version_list = make_list(
      '5.0(3)A1(1)',
      '5.0(3)A1(2)',
      '5.0(3)A1(2a)',
      '5.0(3)U1(1)',
      '5.0(3)U1(1a)',
      '5.0(3)U1(1b)',
      '5.0(3)U1(1c)',
      '5.0(3)U1(1d)',
      '5.0(3)U1(2)',
      '5.0(3)U1(2a)',
      '5.0(3)U2(1)',
      '5.0(3)U2(2)',
      '5.0(3)U2(2a)',
      '5.0(3)U2(2b)',
      '5.0(3)U2(2c)',
      '5.0(3)U2(2d)',
      '5.0(3)U3(1)',
      '5.0(3)U3(2)',
      '5.0(3)U3(2a)',
      '5.0(3)U3(2b)',
      '5.0(3)U4(1)',
      '5.0(3)U5(1)',
      '5.0(3)U5(1a)',
      '5.0(3)U5(1b)',
      '5.0(3)U5(1c)',
      '5.0(3)U5(1d)',
      '5.0(3)U5(1e)',
      '5.0(3)U5(1f)',
      '5.0(3)U5(1g)',
      '5.0(3)U5(1h)',
      '5.0(3)U5(1i)',
      '5.0(3)U5(1j)',
      '6.0(2)A1(1)',
      '6.0(2)A1(1a)',
      '6.0(2)A1(1b)',
      '6.0(2)A1(1c)',
      '6.0(2)A1(1d)',
      '6.0(2)A1(1e)',
      '6.0(2)A1(1f)',
      '6.0(2)A1(2d)',
      '6.0(2)A3(1)',
      '6.0(2)A3(2)',
      '6.0(2)A3(4)',
      '6.0(2)A4(1)',
      '6.0(2)A4(2)',
      '6.0(2)A4(3)',
      '6.0(2)A4(4)',
      '6.0(2)A4(5)',
      '6.0(2)A4(6)',
      '6.0(2)U1(1)',
      '6.0(2)U1(1a)',
      '6.0(2)U1(2)',
      '6.0(2)U1(3)',
      '6.0(2)U1(4)',
      '6.0(2)U2(1)',
      '6.0(2)U2(2)',
      '6.0(2)U2(3)',
      '6.0(2)U2(4)',
      '6.0(2)U2(5)',
      '6.0(2)U2(6)',
      '6.0(2)U3(1)',
      '6.0(2)U3(2)',
      '6.0(2)U3(3)',
      '6.0(2)U3(4)',
      '6.0(2)U3(5)',
      '6.0(2)U3(6)',
      '6.0(2)U3(7)',
      '6.0(2)U3(8)',
      '6.0(2)U3(9)',
      '6.0(2)U4(1)',
      '6.0(2)U4(2)',
      '6.0(2)U4(3)',
      '6.0(2)U4(4)',
      '6.1(2)I2(2a)',
      '6.1(2)I2(2b)',
      '6.1(2)I3(1)',
      '6.1(2)I3(2)',
      '6.1(2)I3(3)',
      '6.1(2)I3(3a)',
      '7.0(3)I1(1)',
      '7.0(3)I1(1a)',
      '7.0(3)I1(1b)',
      '7.0(3)I1(1z)'
    );
  }

  if (product_info.model =~ "^5[56][0-9][0-9]"){
    cbi = 'CSCvt67739';
    version_list = make_list(
      '5.2(1)N1(1)',
      '5.2(1)N1(1a)',
      '5.2(1)N1(1b)',
      '5.2(1)N1(2)',
      '5.2(1)N1(2a)',
      '5.2(1)N1(3)',
      '5.2(1)N1(4)',
      '5.2(1)N1(5)',
      '5.2(1)N1(6)',
      '5.2(1)N1(7)',
      '5.2(1)N1(8)',
      '5.2(1)N1(8a)',
      '5.2(1)N1(8b)',
      '5.2(1)N1(9)',
      '5.2(1)N1(9a)',
      '5.2(1)N1(9b)',
      '6.0(2)N1(1)',
      '6.0(2)N1(1a)',
      '6.0(2)N1(2)',
      '6.0(2)N1(2a)',
      '6.0(2)N2(1)',
      '6.0(2)N2(1b)',
      '6.0(2)N2(2)',
      '6.0(2)N2(3)',
      '6.0(2)N2(4)',
      '6.0(2)N2(5)',
      '6.0(2)N2(5a)',
      '6.0(2)N2(5b)',
      '6.0(2)N2(6)',
      '6.0(2)N2(7)',
      '7.0(0)N1(1)',
      '7.0(1)N1(1)',
      '7.0(2)N1(1)',
      '7.0(3)N1(1)',
      '7.0(4)N1(1)',
      '7.0(4)N1(1a)',
      '7.0(5)N1(1)',
      '7.0(5)N1(1a)',
      '7.0(6)N1(1)',
      '7.0(6)N1(2s)',
      '7.0(6)N1(3s)',
      '7.0(6)N1(4s)',
      '7.0(7)N1(1)',
      '7.0(7)N1(1a)',
      '7.0(7)N1(1b)',
      '7.0(8)N1(1)',
      '7.0(8)N1(1a)',
      '7.1(0)N1(1)',
      '7.1(0)N1(1a)',
      '7.1(0)N1(1b)',
      '7.1(1)N1(1)',
      '7.1(1)N1(1a)',
      '7.1(2)N1(1)',
      '7.1(2)N1(1a)',
      '7.1(3)N1(1)',
      '7.1(3)N1(2)',
      '7.1(3)N1(2a)',
      '7.1(3)N1(3)',
      '7.1(3)N1(4)',
      '7.1(3)N1(5)',
      '7.1(4)N1(1)',
      '7.1(4)N1(1a)',
      '7.1(4)N1(1c)',
      '7.1(4)N1(1d)',
      '7.1(5)N1(1)',
      '7.1(5)N1(1b)',
      '7.2(0)N1(1)',
      '7.2(1)N1(1)',
      '7.3(0)N1(1)',
      '7.3(0)N1(1a)',
      '7.3(0)N1(1b)',
      '7.3(1)N1(1)',
      '7.3(2)N1(1)',
      '7.3(2)N1(1b)',
      '7.3(2)N1(1c)',
      '7.3(3)N1(1)',
      '7.3(4)N1(1)',
      '7.3(4)N1(1a)',
      '7.3(5)N1(1)',
      '7.3(6)N1(1)',
      '7.3(6)N1(1a)',
      '7.3(7)N1(1)',
      '7.3(7)N1(1a)'
      );
  }

  if (product_info.model =~ "^60[0-9][0-9]"){
    cbi = 'CSCvt67739';
    version_list = make_list(
      '6.0(2)N1(1)',
      '6.0(2)N1(1a)',
      '6.0(2)N1(2)',
      '6.0(2)N1(2a)',
      '6.0(2)N2(1)',
      '6.0(2)N2(1b)',
      '6.0(2)N2(2)',
      '6.0(2)N2(3)',
      '6.0(2)N2(4)',
      '6.0(2)N2(5)',
      '6.0(2)N2(5a)',
      '6.0(2)N2(5b)',
      '6.0(2)N2(6)',
      '6.0(2)N2(7)',
      '7.0(0)N1(1)',
      '7.0(1)N1(1)',
      '7.0(2)N1(1)',
      '7.0(3)N1(1)',
      '7.0(4)N1(1)',
      '7.0(4)N1(1a)',
      '7.0(5)N1(1)',
      '7.0(5)N1(1a)',
      '7.0(6)N1(1)',
      '7.0(6)N1(2s)',
      '7.0(6)N1(3s)',
      '7.0(6)N1(4s)',
      '7.0(7)N1(1)',
      '7.0(7)N1(1a)',
      '7.0(7)N1(1b)',
      '7.0(8)N1(1)',
      '7.0(8)N1(1a)',
      '7.1(0)N1(1)',
      '7.1(0)N1(1a)',
      '7.1(0)N1(1b)',
      '7.1(1)N1(1)',
      '7.1(1)N1(1a)',
      '7.1(2)N1(1)',
      '7.1(2)N1(1a)',
      '7.1(3)N1(1)',
      '7.1(3)N1(2)',
      '7.1(3)N1(2a)',
      '7.1(3)N1(3)',
      '7.1(3)N1(4)',
      '7.1(3)N1(5)',
      '7.1(4)N1(1)',
      '7.1(4)N1(1a)',
      '7.1(4)N1(1c)',
      '7.1(4)N1(1d)',
      '7.1(5)N1(1)',
      '7.1(5)N1(1b)',
      '7.2(0)N1(1)',
      '7.2(1)N1(1)',
      '7.3(0)N1(1)',
      '7.3(0)N1(1a)',
      '7.3(0)N1(1b)',
      '7.3(1)N1(1)',
      '7.3(2)N1(1)',
      '7.3(2)N1(1b)',
      '7.3(2)N1(1c)',
      '7.3(3)N1(1)',
      '7.3(4)N1(1)',
      '7.3(4)N1(1a)',
      '7.3(5)N1(1)',
      '7.3(6)N1(1)',
      '7.3(6)N1(1a)',
      '7.3(7)N1(1)',
      '7.3(7)N1(1a)'
      );
  
  }

  if (product_info.model =~ "^70[0-9][0-9]")
  {
    cbi = 'CSCvt66624';
    smus['7.3(6)D1(1)'] = 'CSCvt66624';
    version_list = make_list(
      '5.2(1)',
      '5.2(3)',
      '5.2(3a)',
      '5.2(4)',
      '5.2(5)',
      '5.2(7)',
      '5.2(9)',
      '5.2(9a)',
      '6.2(10)',
      '6.2(12)',
      '6.2(14)',
      '6.2(14a)',
      '6.2(14b)',
      '6.2(16)',
      '6.2(18)',
      '6.2(2)',
      '6.2(20)',
      '6.2(20a)',
      '6.2(22)',
      '6.2(24)',
      '6.2(2a)',
      '6.2(6)',
      '6.2(6a)',
      '6.2(6b)',
      '6.2(8)',
      '6.2(8a)',
      '6.2(8b)',
      '7.2(0)D1(1)',
      '7.2(1)D1(1)',
      '7.2(2)D1(1)',
      '7.2(2)D1(2)',
      '7.2(2)D1(3)',
      '7.2(2)D1(4)',
      '7.3(0)D1(1)',
      '7.3(0)DX(1)',
      '7.3(1)D1(1)',
      '7.3(2)D1(1)',
      '7.3(2)D1(1d)',
      '7.3(2)D1(2)',
      '7.3(2)D1(3)',
      '7.3(2)D1(3a)',
      '7.3(3)D1(1)',
      '7.3(4)D1(1)',
      '7.3(5)D1(1)',
      '7.3(6)D1(1)'
    );
  }

  if (product_info.model =~ "^90[0-9][0-9]")
  {
    cbi = 'CSCun53663';
    version_list = make_list(
      '6.1(2)I1(2)',
      '6.1(2)I1(3)',
      '6.1(2)I2(1)',
      '6.1(2)I2(2)',
      '6.1(2)I2(2a)',
      '6.1(2)I2(2b)',
      '6.1(2)I2(3)',
      '6.1(2)I3(1)',
      '6.1(2)I3(2)',
      '6.1(2)I3(3)',
      '6.1(2)I3(3a)',
      '7.0(3)I1(1)',
      '7.0(3)I1(1a)',
      '7.0(3)I1(1b)',
      '7.0(3)I1(1z)'
    );
  }
}

if (empty_or_null(cbi)) audit(AUDIT_HOST_NOT, 'an affected model');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info.version,
  'bug_id'   , cbi,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE,
  smus:smus
);

