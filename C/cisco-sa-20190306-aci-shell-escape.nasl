#TRUSTED 31746cd0c1b2d5eee2aab439d27968b681391ee33a3e39907fc8d1f5c08189441c5fa73296aa06f3499da10bb4b6636bcf240777d3efba3c055448d0a2628b546f3c4448528c5d9a8f888a4650ebd72ea535452fef7f31a59698409e2161dceba672275ada35247cb9320d9fd98291f31a4ac53d727e49389156ba46c8d69d33035af8f1e7b6ec4c674fdaeb493aadc2e2bf577063fb2be246b849a458a6dc89027ad0cc0f8456c1336cd04c71889689b67685d8e6696c55c01971223351b33b0b3cb2af1f57cebceb806ac1b75e1fa176234dc6569ade122654db09f38387bc5c5d71f0b10fa2c09927a4179873d339433d255b89fb091c72e4ca33bf8a5890e8b74d0bd2b2a6efec0199be392ad92df2a937e8194354d7a1bb9ac2be059c6861771dfd8d028b144d442dc2052b09078a2eaa29e0902692d9844a8c5a1fd599b392ed34e90f5fca0871fed8693a6117b1afd3245fd44f206197c5583c3416a30d3641b0978129600c2ae35b451adb2697bbce3c6f9e692e7f0ccb971bdc0f0f19be2097049c36627702f74c86c4280ca3afd362b77c791ab7763998bb5471b1aef325bdddbf458095ff21aebaec365d732ab1053e0c4d5aab3e930584283215b62bc77d3b8574c867d6959f2d87264d76a9adc41c40623b85616bf4180bb79861a2b41c0968b343a37db0c4bdc3f5693b880e60173af8578aa2c45792a3ddad
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136978);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/04");

  script_cve_id("CVE-2019-1591");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm52063");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-aci-shell-escape");

  script_name(english:"Cisco Nexus 9000 ACI Mode Shell Escape Vulnerability (cisco-sa-20190306-aci-shell-escape)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is vulnerable to shell escape due to missing patch. (cisco-sa-20190306-aci-shell-escape)");
  script_set_attribute(attribute:"description", value:
"A shell escape / privilege escalation vulnerability exists in ACI Mode due to insufficient 
sanitization of user-supplied input. Therefore, an authenticated, remote attacker can exploit this, 
via a specifically crafted CLI command, to escape the ACI shell and gain root access to the system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-aci-shell-escape
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6e5e93f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm52063");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvm52063");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1591");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device", "Host/aci/system/chassis/summary");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ '^(90[0-9][0-9])' || empty_or_null(get_kb_item("Host/aci/system/chassis/summary")))
  audit(AUDIT_HOST_NOT, 'affected');

# Inconsistant reporting from Cisco on fixed version. Fix version assigned based on Cisco CVRF, vuln versions listed as 'prior versions'.

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '14.0(3d)'},
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm52063'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
