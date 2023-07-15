#TRUSTED 5385dcc3afde5c373b1e1c4d8f9a3eeca7334736da061002e17cafb74d91afbcc89feb066f7733033c965c497cb871e53cbfa1166d000fdea5af0cd98792b484432bd054c0f4558c2a37146d12492ff7a9d9508a4964e93899bea24c2827939450d7bf20aad8eaabf12b7658747becd48425a5457cad0bda5e7198b0bef51168f95cbf207cc5d20635d549f989fb70a901c0bcda487a7cad25ed1501983a57f42056841ced6e0dac445f798243f0f75ffd5cdf3fee0d9061a1c2172d900a62e7d84320291ff94bd2ca20d088adc8819f0ff56442db1d810bb93513f1808744c88f3622f2535129da0a77701b5f049dd60c8800fbb7df1ae7e48e9be63996eeae7f36cb9fd8432940664b9caf97aea6c3e9e891023311b8d1fe082e2ec7ddc0e1142223306dbb5abfac44ffc4333d094b5713038d700c0a5b4fe084be3a04df05c483e9d60c6d32fd94194f0f659f6bf6342af4fb389f2cd15a67ebcd325009f779755e9f0ce1e89d8e1c510c352c9f036172b5c882a1bac3ae9c3fa44d77d751a03b6605205f4d55cad91f705e6ace1422273b0c8158a45535489e116e78bb617c97d49c26e46b0960f5a9e32a1073f7b2451c47d2f2c649dedc4e5ac8ca854357f4277005a06e2b32683083f33b2d1c20c79c2f307ada866de32b6aca73a681cc8fd361b445533a4c6bd0ddfdce302e97bdb86aad5af12ec79f9fa2aa13082e
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142490);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/24");

  script_cve_id("CVE-2020-27129");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv21747");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-privilege-zPmMf73k");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage Software Command Injection (cisco-sa-vmanage-privilege-zPmMf73k)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a command injection vulnerability in 
its remote management feature due to insufficient validation of commands to the remote management CLI. An 
authenticated, local attacker can exploit this, by sending specially crafted requests to an affected host, to execute 
arbitrary commands and potentially gain elevated privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-privilege-zPmMf73k
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6754cacc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv21747");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv21747");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27129");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(88);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'20.3.1'},
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv21747',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
