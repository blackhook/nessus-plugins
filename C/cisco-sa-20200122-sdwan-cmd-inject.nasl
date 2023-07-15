#TRUSTED 506a5b7f73c26c1f151110ce81517ca6e9a8a4cfe904935374b68e352d27d2ed18a5a1144d5e57ceff8fcb685b04b84cca86394ccb3f683722c0133bc4454f8def25ec29ddf2e652dfa4218cb9b6d34138db294b765573eee994534fb0cfa7e1cf1fe5804925fb60c3156ac2ab5026de64652fb69caaf04d44cb930f9a8618aa08a6a13f9b6d13697a5dcc2ebe8ff7bb8946a9787a5ce2d1412d41829a9fef3acaf194a89d57dd764dca57ee13f95f9bf96b9bafb48107d28dc0ced7a866548ba234482bec72157b8b662966463a98a7f7d0026e3c81a0627085c3b6e202d9c1e046046d21b8bd54b9cd9fc5f36573f0c4a0f0768ce4c856384315b41e0584b806f3aea224b7e8df5ea136da302fe1c5cbba870d59107f0a79addeb8286c0e6ef039ebec535e7fec75d82b6ce1b359585077de623e620c3bb53083e60b52f50e0f0477dd9e60478cd1701384a27bc32e54cc2d2b10174a58790d46ca430fe8d47c41753be79538150602859e6a10667a28571d5776783dda40bb84c1694b3ddfcd45e791f3db3c91126587ae3013ea71c9b7978b1693f793b05f835fd541563ed7c832b8fb85852580fb4de0a966eec7c67d37fbbc50008e778e50f25658fb66f142bdc18aa22854f32c731964d1270008463aa2fc35ba405d113c5611027d4cf8b1348ee99dd8cd16c8858f324eec86ddcf31b2c74afc301b6da8f448a7f8b1
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147650);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/12");

  script_cve_id("CVE-2019-12629");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi70009");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200122-sdwan-cmd-inject");

  script_name(english:"Cisco SD-WAN vManage Command Injection (cisco-sa-20200122-sdwan-cmd-inject)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco SD-WAN vManage installed on the remote host is prior to 18.3.0. It is, therefore, affected by a
vulnerability as referenced in the cisco-sa-20200122-sdwan-cmd-inject advisory.

  - A vulnerability in the WebUI of the Cisco SD-WAN Solution could allow an authenticated, remote attacker to
    inject and execute arbitrary commands with vmanage user privileges on an affected system. The
    vulnerability is due to insufficient input validation of data parameters for certain fields in the
    affected solution. An attacker could exploit this vulnerability by configuring a malicious username on the
    login page of the affected solution. A successful exploit could allow the attacker to inject and execute
    arbitrary commands with vmanage user privileges on an affected system. (CVE-2019-12629)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200122-sdwan-cmd-inject
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af16326d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi70009");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi70009");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12629");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
    {'min_ver': '0.0','fix_ver': '18.3.0.0'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvi70009',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
