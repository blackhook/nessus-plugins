#TRUSTED 419a83ea65013248c35203e57d0c76f9e751f39a112797c30e8765284d762ca9c9fa45efccb38fb1a93c4d28e97344931d3cb0eba40fc15201d2d3c0ec60948eeb32505166cb73d85f2aec4517186a58edf33ed22a4d11b3cdfd37e20ddb7f9f8380506178efada877f0f143a13b5c16a48797136a94911aced0d4304fd80dca274621e71d6e828340f26c7d978af797ca078c89043bd7c77844c78b4ee2caa64f1ce7a4309079011819f1f4a6ea274180b08fd6311bf28df5b130b128a46724c10df2bb4941971113d4cc57966d9fcd918b08d836d051484af678f14d69dc21af5c24cc86f81d0c1b08c74473d41c3cf052680ebd611dea90b9716872ae8efe99c50fab8aca52a78d4d210adcaed3ab2e9dfcd7c40c02276e3ef871c28538fff86e8800b7a29ff8d61dd0a4677058ebff50f295c68dd85b80df027f7c6be2625fc0dd0e216bbc3bcf98d77f6341f4121ad119fa1bb97fb2e93115bfb85c3b9f63fefebbca1c1b75e68f5bd55ece236d57b2c97c705b7ab16dbdd4812db5d3d2a0fc1249d364e079aaf14b8ed09c06bf18299338a5cc97d7fcd458e4778741dc13ecd274afe6e6557ab1700bbaa70bdbe4cbc5d5f51646331a0bd1b91848409f3f5c8d01e26821ba603534d8733d289c7154e74b34ab1b67798b09048bb2cc0e0b49c4ac3fa00455c0f684ea5811bc32092d0fbdff16c3405b95e0f957211151
#TRUST-RSA-SHA256 31a8de9b3c9cacafd834fa595de4633bbe05566b725750fef1bea06b3d09f7bf162acf786b1d704054554901b6618826c32f272624e5a42bf8e42b072af9a0a580deabee1b3796874a09419824baa2de265cad61ecb689554daf0513fd64b36f5343ebac8e3a66e1b41799513014f54401e31a2df32dcc67a7d1278aa466e3b0060a8cb2a3c3a336482b201475032deb5b916645345babd95ce20e6aa8ff83ab9958545e44826e3df7c0da4b3f9452af0ef259134ac5e60ee358519847371c10b7462bdf843a8d3f4abf9a4ab3adb4c610a7321236681e0ad11202a4325f0fcb00b8e708bec81ff66fb79eb787047505b94de88a2e2b0203677f0b4bcbc773f050a02b02da439479a9eb6274605110adc79f52b7e367005adc53cd0d9a8ebcaf35a26354212ab0d8fd9b54330ae029842be142ad8a21b682c2ba5dbdf15de83a0a5529ddbbc920bfdc5f716c78b188f78db967ca98200db72a83af072289ed2ee63d488c8929017b8c5a5713c3dbb5041a5f99f6482f7f7a0da298718bc791e88e0c92ee9fd78ada04034d411ea7b15887cad62d644729e7f76f75403b39bddc1270471301a091bf8b728f4438c25b7a8fb10eadf158d0554295897ed413e6590371e7d6269585059f7d13b318200458be0edc231416313a5370837f9ba3f360f56d9a8313a51ea3c84cb1a75c2c38202db0b2b2ac5187363c2945746d2191cd
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137136);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3254");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp16945");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp16949");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-mgcp-SUqB8VKH");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Firepower Threat Defense (FTD) DoS (cisco-sa-asaftd-mgcp-SUqB8VKH)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco Firepower Threat Defense (FTD) due to inefficient memory
  management in its Media Gateway Control Protocol (MGCP) inspection component. An unauthenticated, remote attacker can 
  exploit this issue, by sending specially crafted packets to an affected device, to cause a DoS condition.

  Please see the included Cisco BIDs and Cisco Security Advisory for more information.

  Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
  number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-mgcp-SUqB8VKH
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84c4cd75");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp16945");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp16949");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco Security Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_asa_firepower_version.nasl", "cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

# Hotfix detection not yet in place.
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

vuln_ranges = [
  {'min_ver' : '0.0',    'fix_ver': '6.2.3.16'},
  {'min_ver' : '6.3.0',  'fix_ver': '6.3.0.4'},
  {'min_ver' : '6.4.0',  'fix_ver': '6.4.0.4'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp16945, CSCvp16949',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
