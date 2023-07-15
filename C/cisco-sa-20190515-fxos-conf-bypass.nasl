#TRUSTED a57f5d084af707c9ff0c08507e8fc2d8a466be07ceabd83ea4e04db7ba1b6d777e2226f70a8f7432a16898af3d7880bb12eee918535ae2c0d81701eeee5bbdccd8cff469eed7d4a863f6e338c3fd91130f70b7302bf8e71b3f09d78079cde4ae81aef20a98fd678972576ff870eb5fed07f88cec45141189211d4bdaffbd3f68600dcb39f7fec8edaf7d8fffca99cd22e7cfaa3a0455a583b725fcc0d88261909223a4ab39fa2b6452a4da228fbb26d5a64b53cda977b94483c68ba9632521b5615a586b46434edeb68ab131162cf5447bbfbc9485d83ba62c5c237554057d4f79931d957ec753507edd2ddb8c11c542576e1976f9ed7329c760d85ab8be2452ee99d25b9e811e73e56cb0d2ba375a70130e0d2e3bcde61ac76f52b47543c8b7a210134a527f1f2841966390a2887d5cd7142e738b1e8b6fef6596717a148c585fd8323ad26fdc4de9ce435d6f26307b0df01b5e01e5354630eecb6265165bfa8f6b5b3036f0669be24889204e5a5159c9949b027c85b619b0fc386e56cfbfbb7f76e3f9914fdab220a252dffbe70f0966480c0b5f5e6e0779447fc4df37be73aa6de51772c068748fb47fee62958e23f21f8b5b5b7fc441a759c86adfddc7b40503a0b3f01ceacedde3cae6e92c546273718c88e2518509ddb01d4c61edfe013dca2b7a42ac8a6fba8751f9ce06cd3e9de1068dd528c9cef545de2c762fef9c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132720);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2019-1728");
  script_bugtraq_id(108391);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96584");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-conf-bypass");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco FXOS Software Secure Configuration Bypass (cisco-sa-20190515-nxos-conf-bypass)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software is affected by a configuration bypass vulnerability due
to a lack of proper validation of system files when the persistent configuration information is read from the file
system. An authenticated, local attacker can exploit this, by authenticating to the device and overwriting the
persistent configuration storage with malicious executable files. An exploit allows the attacker to run arbitrary
commands at system startup with root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-conf-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a24f9c8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96584");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi96584.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1728");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('vcf.inc');
include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

app_info = vcf::get_app_info(app:'FXOS');
product_info = make_array('model' , app_info['Model'], 'version' , app_info['version'], 'name', 'FXOS');

if(
  isnull(product_info['model']) ||
  product_info['model'] !~ "^(41|93)[0-9]{2}$"
)
  audit(AUDIT_HOST_NOT, 'affected');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.4.1.101'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi96584',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
