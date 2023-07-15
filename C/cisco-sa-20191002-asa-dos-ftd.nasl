#TRUSTED 025d85b9f1343f59c5227e32cfa8cb2e983d48f2c15dc89b1f1dcebdaf5f8b348ce0cab9b75fe9426a0fb0a363e39078a9ae2fd85589d6600565ccccbc6672b8cc90e2561c3b884177959f8dd9853ae613208bc7ed2d7c0c5823ac28caba85ee6080969db3084572b390356381d7d0818447873b192f006563f022f82534faa3493cf45c482b4bb82410e213af248a322c0f9681b774d1844ce5a628956c482dfa3187bee38e9768fed0558df71de6bdafb42bbe36d846064f5f516644072194ab5b89208aae3d0216cbc6bce2a73a31831de7007038bbc0b15d3483aee22a79dbef08dab19b1215e09f1a57660bb95992f54beec7f3d0a4ce3881045133f7cc63177feec9456086fd9829fa6045bdc033c87cf3af1c4ee70d5de040b9b4a479c256d4b1e530f14fb6d8699444bb85e20e8a415f93386b9add0ae31496c130f85bfe6f604f43eb24a562d107ac33099b33ca1fe1fb4134adcd3452baa9901cf91c2068218da0864bbdad1e26337227e0eb3b8f60419e2483f849db1ec20af96099e5bdec7864da44d1d47da20c53869f4408c773b1071c7538ff91da5c90b0a0457e85e1af3a837a38340ab5a4b38a7a669d7c7d7db748e670cdf27de480bc42e2d8ffcefa5a3f942fde967ffc82e94d54f98a093862bdd9aec49c12f3fd5ca1232c721ca55429581edd0605eb3cbf7a1e4ecae72b40d00d3b4c7ad0c8976254
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133851);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/07");

  script_cve_id("CVE-2019-12673");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo83169");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-asa-dos");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco Firepower Threat Defense DOS (cisco-sa-20191002-asa-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability");
  script_set_attribute(attribute:"description", value:
"A denial of service vulnerability exists in the FTP inspection engine of Firepower Threat Defense (FTD) software
due to insufficient validation of FTP data. An unauthenticated, remote attacker can exploit this to cause to cause
the system to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-asa-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a727a568");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo83169");
  script_set_attribute(attribute:"solution", value:
"Update to a fixed version based on your hardware. Please refer to Cisco bug ID CSCvo83169.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12673");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '6.2.3.15'},
  {'min_ver' : '6.3',  'fix_ver' : '6.3.0.5'},
  {'min_ver' : '6.4',  'fix_ver' : '6.4.0.4'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['inspect_ftp'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo83169',
  'cmds'     , ['show running-config']
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds,
  workaround_params:workaround_params
);
