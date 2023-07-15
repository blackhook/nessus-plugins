#TRUSTED 39a55fc7184787731863a4d5b5fa3342bac1617bf19e03364dbbc9bdbd76d6cb20793c620dc017af6b3b40cd7a55af9de9e58c441a7f6913906cb4a69f2887f9fe9ecc06e11dc10a8f44484320ae89f7eeddade9b7d59b25dfbc3ecb0afa56ca3f5b68b6a160572bb48daa4969990b3d49ac9c48e0424e04208cae7e38e93b9af89629f57c60d4d52cd0be660f0798c2a5f83c75e6408eed3323ea25e0130096fb184c2f65f427f6202468621f97565ca369858564bd3685baaaa1167a7ebc64bbc308790fd8e257bdc07a3c30ebae20be174e2a033c3cf432a0009e52db3fa43bc8214fe72ce5796f61e7c5ffe800f722af3213d168f6ee7b260bbbf54599dea8228e5e16c12e56470730f4e54dac47a8381e43c7c01c88675200d284d564de37d2c60923857c3c7adb7c090262a233235e259b0a04715732e4cf3c1b08e8fe5008596b62782eea225ade56248a37e925f1bb627adc08867a9a23c0b661251bfa73be8c786e95a19b67505153949ee89e742756cab33e9dbcec65986c93cf1f6ec4e2eabb8cd993f30a21f727c1e9809c63f2a155d7fc620f87e34706db73d89f0a7040936440bd267eb268d0f5aa03b93f0b7ad0266b6e77ecc1c52d761d3a5beb48d5b0a02b1599427302492dea40529d88f76dc2ecc24dcb687ad82c3118c83d20d55fa36878db82b2894a61807fd416b7179b3d24c39703d9c9ee5e8d63
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133850);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/07");

  script_cve_id("CVE-2019-12673");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo83169");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-asa-dos");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco Adaptive Security Appliance DOS (cisco-sa-20191002-asa-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability");
  script_set_attribute(attribute:"description", value:
"A denial of service vulnerability exists in the FTP inspection engine of Cisco Adaptive Security Appliance (ASA) software
due to insufficient validation of FTP data. An unauthenticated, remote attacker can exploit this to cause to cause the system
to stop responding.

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

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '9.6.4.34'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8.4.10'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9.2.56'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.30'},
  {'min_ver' : '9.12',  'fix_ver' : '9.12.2.5'}
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
