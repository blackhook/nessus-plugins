#TRUSTED 0b3f379c5f960249ea02f992002c311415bfc144d3c3ce1e4454411a7addad280e18b9e07672a5d7039cf2613afbe5ed26f9eb402ef598b555d0dc45d21a42896fc7e472b0d3700c1994c07a614b32ffaa16da619c0d0a338fe6274c3cca45cd587e44b7351940e4d05ac94fa07296959738fee5ca953fac4d120962e8f2fada74412759fc6408d641bc57097f7cdcdcde78c05eab108c06ca4f622995d0d9ccbfdf435c61db3b71e8c660a714afd3f7dc2d5242fa6b89840f56c7893124903dcc342b2da23ef887348074ecb7ca8cc5b0d076612d4796769c1165a42d727fb4448d64dc7974276a2dfccb4cbea0f8f47aba5555ed32a05e5baf32ebea512376ab2f52175f1ed1b51d26a2cf81e3a27043366ad29e86b61a0f4d935e2d026211c4d635bb8f3bc78c02321961fa7d48c4a58a6584c38bdd8a7e3a1228961bc900c0a2d5cced9ee1522ade10413887902bac5bfacb003f3d65637816bcd57bfbffec23841cc8f8467111139ad3f99b4b2b287d05fb1a24d7da2f94625b5de89bda160e71e8e9beee8ddaf8b1e8b2be09d8140f255a675c322e08d4ecac366e5e06f2e215587d4b1bbcf288a7e0a8c5f21086c4ba0c21090b84f8277426779749cac4fb2ab52a2dd2f346cbef728b35c31b4443f396064fe62c1e24987d39dd7023b166587f9312605d94f1ffeb1e7d83e8b26020d8bdc453acdca06b4e110215f5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140185);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/18");

  script_cve_id("CVE-2020-3415");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr89315");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-dme-rce-cbE3nhZS");
  script_xref(name:"IAVA", value:"2020-A-0394");

  script_name(english:"Cisco NX-OS Software Data Management Engine Remote Code Execution (cisco-sa-nxos-dme-rce-cbE3nhZS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a remote code execution vulnerability. The
vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability by sending a
crafted Cisco Discovery Protocol packet to a Layer 2-adjacent affected device. A successful exploit could allow the
attacker to execute arbitrary code with administrative privileges or cause the Cisco Discovery Protocol process to
crash and restart multiple times, causing the affected device to reload and resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-dme-rce-cbE3nhZS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f83e12a0");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr89315");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr89315");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3415");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
cbi = '';

if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ "^9[0-9]{3}")
  {
    cbi = 'CSCvr89315';
    version_list = make_list(
      '7.0(3)F1(1)',
      '7.0(3)F2(1)',
      '7.0(3)F2(2)',
      '7.0(3)F3(1)',
      '7.0(3)F3(3)',
      '7.0(3)F3(3a)',
      '7.0(3)F3(4)',
      '7.0(3)F3(3c)',
      '7.0(3)I5(1)',
      '7.0(3)I5(2)',
      '7.0(3)I5(3)',
      '7.0(3)I5(3a)',
      '7.0(3)I5(3b)',
      '7.0(3)I6(1)',
      '7.0(3)I6(2)',
      '7.0(3)I7(1)',
      '7.0(3)I7(2)',
      '7.0(3)I7(3)',
      '7.0(3)I7(4)',
      '7.0(3)I7(5)',
      '7.0(3)I7(5a)',
      '7.0(3)I7(3z)',
      '7.0(3)I7(6)',
      '7.0(3)I7(7)',
      '9.2(1)',
      '9.2(2)',
      '7.0(3)IA7(1)',
      '7.0(3)IA7(2)'
    );

    workarounds = make_list(
      CISCO_WORKAROUNDS['nxos_cdp'],
      CISCO_WORKAROUNDS['nxos_jumbo_frames_enabled']
    );
  }
  else if (product_info.model =~ "^3[0-9]{3}")
  {
    cbi = 'CSCvr89315';
    version_list = make_list(
      '7.0(3)F3(1)',
      '7.0(3)F3(2)',
      '7.0(3)F3(3)',
      '7.0(3)F3(3a)',
      '7.0(3)F3(4)',
      '7.0(3)F3(3c)',
      '7.0(3)F3(5)',
      '7.0(3)I5(1)',
      '7.0(3)I5(2)',
      '7.0(3)I5(3)',
      '7.0(3)I5(3a)',
      '7.0(3)I5(3b)',
      '7.0(3)I6(1)',
      '7.0(3)I6(2)',
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
      '9.2(1)', 
      '9.2(2)',
      '9.2(2t)', 
      '9.2(2v)', 
      '7.0(3)IM7(2)'
    );

    workarounds = make_list(
      CISCO_WORKAROUNDS['nxos_cdp'],
      CISCO_WORKAROUNDS['nxos_dme_enabled'],
      CISCO_WORKAROUNDS['nxos_jumbo_frames_enabled']
    );
  }
}

if (empty_or_null(cbi)) audit(AUDIT_HOST_NOT, 'an affected model');

workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info.version,
  'bug_id'   , cbi,
  'cmds'     , make_list('show running-config', 'show version', 'show policy-map system type network-qos')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE,
  require_all_workarounds:TRUE
);

