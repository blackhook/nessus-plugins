#TRUSTED ad732e024581ecdb0dae0098c2b5b616ed382a9fbe1cd8c82c646370b45c6bf306a0a61d3b17e4c2c7cd890dc0b50ae1df9534cae48444ebedabbfcbb4ae2fb262c47bacee944c1087900283cb18e708bc054e341f783c6d749ff79e27465e4967ba332373f0b36af4e42b91044fec247ed1f8b26d9bb56d79c028893f520e13eff6e889a6657634661eff2f56798152e1b3b32196a4e21f87a55ec8874003c3382cdb4cdc097e82067de4dc05f6a31e7fd510186035a00fc11766387fa0e493617f5982e76c5fc6a7d035e55665b4cd8e20aafcc8c1e2affd6bc64144045e495dd3716e3d616c651cc91cee73a47c03a9ef687eb041dd63c7c6083e2746fb8a16708b9b8a2a4e2659985adfbf196b50f29203eef962387887ccf8ab80ee18f72b80005d09b97999e9111f8cf6421813eb9db115431ff731e88cf450c10d7f987ae00a581375adc42bd35253c906b60831c78c9a6bd13193f91a3c9e23c83644fc0758f0a6f370736fce74a8acf865e545ad9bc3e2b717ca405d89b8623282342b8e33812fa6edd6e51a0f1fb05a98ed8856e5bfcfa19efe2c840ce99023369f7d661a4ae2e0fc9490f6fa6960901161b1a985fbe2ef9c1d8c1cd2c22993c20eefc96407d602f5141ed312fa9188435287a859e8d4bc82c30fd206541fe2c37abadd2b59a89e75c6ea6d3013d5347c05695f3c051ba88c4bd15aebb7fffeb216
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134566);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3167");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr49734");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-fxos-ucs-cmdinj");
  script_xref(name:"IAVA", value:"2020-A-0085");

  script_name(english:"Cisco FTD Software CLI Command Injection (cisco-sa-20200226-fxos-ucs-cmdinj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a vulnerability in the CLI due to
insufficient input validation. An authenticated, local attacker can exploit this, by including crafted arguments to
specific commands, in order to execute arbitrary commands on the underlying OS with the privileges of the currently
logged-in user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200226-fxos-ucs-cmdinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5d34d6d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr49734");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr49734.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3167");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');
product_info['model'] = product_info['Model'];

if(product_info['model'] !~ "^(10|21)[0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '6.2.2',  'fix_ver': '6.2.3.16'},
  {'min_ver' : '6.3.0',  'fix_ver': '6.4.0.8'},
  {'min_ver' : '6.5.0',  'fix_ver': '6.5.0.2'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr49734',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
