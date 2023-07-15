#TRUSTED 95974d0204592ba4eb177e28b8f9062f8ce71c044182b1379bf2634a498a75fddee5b0549f00455bda34161c61b22a5d122c0c5c3b253debd58602cbda554a62c8ccb956bca15fe9e1b5cf5b7cbd645183d9d1a8ed2d0850a7e15f1648cb229ad34b738f4c97ae21cb4dc20d540614f08b6957133d9ce64c0cb29ac2555d257735109642f0935ce75fd091673703651e28445fdd19a8d4a7d249741140768d0727fab37ce108f5e22bfa9d7d8ec3b5d8e876a7e8ebbaf80310d0301734d6ffd9691d64da92e6b237019662f081d2d8e54dfd46eec09dc72786f3a24846fd8584f07f42cb512edb5034106fd5d1f45841db1beeb0b131d0645a2f0d455140e423b252b47dd717f45b353f8ed3ccde4fbaae6dd58b30b3e4236a64ab5085f1e713dd57e674f94ca0a0132d7d9023d9b7aad6a95c89f831b577866084d21c33897e47fe663d179f63ee9dd2708c7c566fa82abdb96b77fff49c8e9313098b20842f2d4243f9f2f4bc535049ff53f86666e629302962d3084f4bfb3d044ee64f0aef0bfb8889080ffc2dd5a2e9f1763badb76537bb8d18a909c2f696610ee0767361d98afd8eec1dbc6fa6ac7dac4d8e2453e0872a96e0ab8cf9453a5481ad0d4268aece1207c689ee8792b4103a7f853cdebdcb424c7e4d9864746b320d72709e9556a12270b82ddc2f23b22d9d46ff5f3b7fc7de50882554757c9303b900bf20a0
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129981);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/25");

  script_cve_id("CVE-2019-1780");
  script_bugtraq_id(108392);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92332");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-fxos-cmdinj-1780");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco FXOS Software Command Injection Vulnerability (CVE-2019-1780)");
  script_summary(english:"Checks the version of Cisco FXOS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cissco FXOS Software is affected by a vulnerability that allows an
authenticated, local attacker with administrator credentials to execute arbitrary commands on the underlying operating
system of an affected device with elevated privileges. The vulnerability is due to insufficient validation of
arguments passed to certain CLI commands. An attacker could exploit this vulnerability by including malicious input as
the argument of an affected command. A successful exploit could allow the attacker to execute arbitrary commands on
the underlying operating system with elevated privileges. An attacker would need valid administrator credentials to
exploit this vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-fxos-cmdinj-1780
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d79e1307");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92332");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi92332");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1780");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');

if(
  isnull(product_info['model']) ||
  product_info['model'] !~ "^(41|93)[0-9]{2}$"
)
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.3.1.130'},
  {'min_ver' : '2.4',  'fix_ver': '2.4.1.122'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi92332'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
