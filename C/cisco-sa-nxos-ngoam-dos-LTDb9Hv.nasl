#TRUSTED 4d53bb02f441b4d601a593d42b9a29f573d34628da68c79363e5ea900a471651f52777bd3a07e61c59becd65f8b737b56b9e8c628352cc7b8c834943ab407b4b95912f1f8d4f801f57615502d3ea25a7f02a2d05f32b9b4015551e3f78d28c8192d91ba6345ef374b753fdc946e3a0266514bb7201e553afd9b01a41c7acc050d78e0f7ecc770f20e9f86df3ef837385df396cbee137764a410a15e41844a8a9d679cf18a90434b9fdff90cafb09d541fb21857e745675c2b5e617f9f13be106d665d3f6acd3a12775dcecd7bcfd87fcfd5834258e6ee6d5d2b9562b582adf31b63f8907d61b02919e6c9b0d30b10e7d195b41e2f9f22f62c95bc25b69d30acbaefab7a2cebc8d2d96b9168f5201fb2abfcfc9d1b3aa237950e1c5fc046459ce53570d1cf4b324b8cb1197f2c7876aad0727ad816d447c2c45c4c82fdf7fd9adf28de9f52191b2c9a63dfb8eb37d90512546588dba5adb2898aeb8cb5299e8d9f526ce15c7603586efc4b24939b918c49741aa5a8c48fa8961dd4efe309037b7d6a732c14811ba25e1e67f438bd65647afee6841cda47065fb6670a9403edd88069cce728701a46cb2c89bab998f06198657e0949fd4eae5063adee6d78583eb5de2751e41f706321faa75672c704a7b7722ef3707afe6a83a9ee1e3e746e0bbf018c10ec42105e3fe70914499e38a45a556ee791ea477ed695b9c93062b082f
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152877);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/02");

  script_cve_id("CVE-2021-1587");
  script_xref(name:"IAVA", value:"2021-A-0398");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx66917");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-ngoam-dos-LTDb9Hv");

  script_name(english:"Cisco NX-OS Software VXLAN OAM DoS (cisco-sa-nxos-ngoam-dos-LTDb9Hv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in the VXLAN Operation, Administration, and Maintenance (OAM) feature 
of Cisco NX-OS Software, known as NGOAM,  due to an improper handling of specific packets with a Transparent 
Interconnection of Lots of Links (TRILL) OAM EtherType. An unauthenticated, remote attacker can exploit this issue by 
sending crafted packets, including the TRILL OAM EtherType of 0x8902, to a device that is part of a VXLAN Ethernet VPN 
(EVPN) fabric causing the affected device to experience high CPU usage and consume excessive system resources.

Note: Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-ngoam-dos-LTDb9Hv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7380f039");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74640");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx66917");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx66917");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1587");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(115);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ "^[39][0-9]{3}")
  audit(AUDIT_HOST_NOT, 'affected');

var version_list = make_list(
  '9.2(1)',
  '9.2(2)',
  '9.2(2t)',
  '9.2(3)',
  '9.2(3y)',
  '9.2(4)',
  '9.2(2v)',
  '9.3(1)',
  '9.3(2)',
  '9.3(3)',
  '9.3(1z)',
  '9.3(4)',
  '9.3(5)',
  '9.3(6)',
  '9.3(5w)',
  '9.3(7)',
  '9.3(7k)',
  '9.3(7a)',
  '10.1(1)'
);

var reporting = make_array(
  'port'     , product_info['port'],
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvx66917',
  'severity' , SECURITY_WARNING,
  'cmds'     , make_list('show vpc brief', 'show running-config')
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var  workaround_params = [WORKAROUND_CONFIG['vpc_alive_adjacency'], WORKAROUND_CONFIG['ngoam_enabled'], {'require_all_generic_workarounds':TRUE}];

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);