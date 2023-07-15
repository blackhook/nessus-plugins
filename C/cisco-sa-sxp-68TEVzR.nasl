#TRUSTED 586fdbb03bd6b7fe1285e9c3b5d13bef2cc727d159ff2498a855b98dac5e8e273e2484cba3fa8083c78a0df77a59d971d4955b8491ed85a3032702bc6e2cb7187a3198c5ff4702eb478948868a642da53d523d37d5d6b18f6fb99e104d2e24f385a8d12fde2fff94a72fc70fcb876488f376f7abf89f48002b9ba425c161bad63b2be333f03b21d22dcd3fed93bf58fb529c865a267ccc107e44d9117ff15b2abcd6996a2d3094403e61250927601f8b5224c6beb03ef97679868dc7e3ac89754e2d0612090d2ddaaaae037ab0c72c26104b7bda9f1ce6535746f5f53e00ccc93f367397c29d88d0e0615678c3f23bb7761356088663e70d85a7e924b919ba0093151e550e825e089d9db3f266feea67847a653baa22edc4b4e25b25dd00dd19bbfc4e40ef877cdbd7b3921dbbe953636e69795f509946e209211c133fa3c2fa6f43f324ccf6c11d9d16928e262b93b40dd0e505416d4051fee70ba03f198f5e27b930d4c9b7df72dc58fb44c8875ff43baa64c812ce12a244ae8126dbb128a8833892996458a6ef515da43d96eadff4b4ec359f606f87e547e058bffd0448b2decb744969e795465c863d7af2453e63e3dedb8cca53a61723c6936c3e3a1561ccacdfac4c39713c81df5350490727af6728af57d65cdfa65fc2481f46a8d1088d093562274bead1cad425c98eb72421675757e070c5def79f80fa488a7c6563
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137656);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/28");

  script_cve_id("CVE-2020-3228");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd71220");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp96954");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt30182");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sxp-68TEVzR");
  script_xref(name:"IAVA", value:"2020-A-0260");

  script_name(english:"Cisco IOS, IOS XE, and NX-OS Software Security Group Tag Exchange Protocol Denial of Service Vulnerability (cisco-sa-sxp-68TEVzR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sxp-68TEVzR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc568213");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd71220");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp96954");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt30182");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvd71220, CSCvp96954, CSCvt30182");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3228");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/19");

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

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('nexus' >!< tolower(product_info.device) || tolower(product_info.model) !~ "^(1000v?|(70[0-9]{2}))")
  audit(AUDIT_HOST_NOT, 'an affected model');

if (product_info.model =~ "^70[0-9]{2}") {
  version_list = make_list('8.0(1)');
}
else if (tolower(product_info.model) =~ "^1000(v)?") {
  version_list = make_list(
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

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd71220, CSCvp96954, CSCvt30182'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['cts_sxp'];

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
