#TRUSTED 474c7f1fdf4dbb7e4b04805b9eaf4c6961f9029fe0d24659d58c2df763be7c1c2417378446eeb271a625aafbca77ef2219b0d6b6b65bb515474f3106ed2e9fb29393e5ec216d6ebacfc8c74cbbe81ebcca1b4a5f4e09d3da41c69a2e56f159e03feafe198f0324bf15ab237c2421651d8e7da96b41f4760c229c139c939c6d3298937798fe2c2200fe46f005fa0b77fafde5014b12571bb9e17f57e6893112474fa2b42b8080abe1774c7bce9b865eaf6c26e583a7d44accd938896af291d0657c2f644454e6d69f6459f404717ff32145a2db41af2dfbe46f2f9a3a3d20359388b1b51c676427a959b75f5cd1297360a6ee462b69c6907de2298d789c98590b0cc341488e7e0419a8c0debdb91cebf7fee7c49454104a9eb46ca45fc5de04b5d380dca246afa45aad158df8b34a71d5bed8017aa799a8734c4dae979ff857a901f78fadf27ffa71d932b8d219021d33ae030e54d3360511c6b423788eecc37cef509e4fd43caa3100255076a59fef3ad708b5507592debd6e0e15b966a18008b01dddcdcde7eaa941cc9bf7cdc4ddb5d114b050d5e13a8371de6f88ec674a97611088e41fe429ecc9d95e82cc23c72b06e1b71495204395aad63b66c3c34a9c03b4b572f5024d4ab5fc77fb52eeac597521cd21f2a28604a9fa346ae9b968de315fe261a9da7479017f1d20855bf4e2f9e38cb589afec97106b8bb68da07de1
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149718);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2021-1368");
  script_xref(name:"IAVA", value:"2021-A-0113");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-udld-rce-xetH6w35");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv96092");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw38984");

  script_name(english:"Cisco FXOS Software Unidirectional Link Detection DoS / Code Execution (cisco-sa-nxos-udld-rce-xetH6w35)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"An arbitrary code execution or denial of service (DoS) vulnerability exists in Unidirectional Link Detection (UDLD)
feature of Cisco FXOS Software due to insufficient input validation. An unauthenticated, adjacent attacker can exploit
this issue by sending crafted Cisco UDLD protocol packets to a directly connected, affected device, to cause the device
to reload, resulting in a DoS condition or arbitrary code execution.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-udld-rce-xetH6w35
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b37d5dc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv96092");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw38984");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv96092 and CSCvw38984");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1368");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/FXOS", "Settings/ParanoidReport");

  exit(0);
}


include('ccf.inc');
include('cisco_workarounds.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'FXOS');

var vuln_ranges = [
  { 'min_ver' : '0.0',  'fix_ver': '2.8.1.143' },
  { 'min_ver' : '2.9',  'fix_ver': '2.9.1.135' }
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv96092, CSCvw38984',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);