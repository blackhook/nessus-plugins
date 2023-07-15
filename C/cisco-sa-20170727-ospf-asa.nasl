#TRUSTED 4a8e45c52b91d1dac19bf74ee0e8c856459810a5d3ccc32f3d63431f60fd07fea036b4378794c6af3b6fb9d0a5a9b70cde999b1ef82aeec24712baa0017049c0c2f32bade9e7e312635320d442c73922667151e82003fa439fd2e3c1b618b8b70454c6a866c18a5d8aced8c73df605d977ce7e300400d197d56708e59c33b2ffbb257c24488a2e92d2ea1335f59734dab20df09587dfef2d69b7c86fbbb4b8ffe12b1a44a7774542c0097951385ae03aa80b8b4e242a911b973d89fd659f5e15defd475aab7ce46c17339c7545245674f74c4336768a57760c1dbcc08b2d1554e7c2d2dd686bf1b1ed5b2e5a391f9207f1446ede789cedacac68155ade14bb4db27ccaa7fc1019d3f60c0571c12073a606d4d32f27d5936d7ed6550de9e4d0c22eabc97173b212d8d543c8e46eb417b12259e8fc364457524ecc47b58d7c40eb512d0d18f6e57df38524b117a6657082d9ddf80c6688c3abe9eb6b73066272626c10fcc0306ade891bbb7374b2ae718fccade968d79005d3728298f4fc4edca17193787b1d31fcd253cec077795c9e1d9ed01dd1705323510e1448c06e275a23852daf900e461e22b35fccfb94991e651d41aea4dc39651a33cd50b98cb4919074f35f3d77eb610f6f8d35ec72be2b56ace2b470d25fea43a5656349df69f1039b1e678153e56d5728ecb5d2814482c046580de717a8a78103c66cd252037357
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131393);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/24");

  script_cve_id("CVE-2017-6770");
  script_bugtraq_id(100005);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve47393");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170727-ospf");

  script_name(english:"Cisco Adaptive Security Appliance Software OSPF LSA Manipulation (cisco-sa-20170727-ospf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance (ASA) Software is affected by a vulnerability
involving the Open Shortest Path First (OSPF) Routing Protocol Link State Advertisement (LSA) database. An
unauthenticated, remote attacker can exploit this, by injecting crafted OSPF LSA type 1 packets, to cause the targeted
router to flush its routing table and propagate the crafted OSPF LSA type 1 update through the OSPF AS domain, allowing
the attacker to intercept or black-hole traffic. Successful exploitation of this vulnerability requires that an attacker
first accurately determine certain parameters within the LSA database on the target router.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170727-ospf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c4d1c57");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve47393");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCve47393.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6770");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

# Affected versions only found on bug ID page, which is not very reliable
if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

# Taking the lowest version from each of the major versions in the 'Known Fixed Releases' of the bug ID page.
vuln_ranges = [
  {'min_ver' : '201.1',  'fix_ver' : '201.1.1.30'},
  {'min_ver' : '101.1',  'fix_ver' : '101.1.1.41'},
  {'min_ver' : '100.13',  'fix_ver' : '100.13.0.167'},
  {'min_ver' : '100.11',  'fix_ver' : '100.11.0.84'},
  {'min_ver' : '99.1',  'fix_ver' : '99.1.20.80'},
  {'min_ver' : '98.1',  'fix_ver' : '98.1.12.151'},
  {'min_ver' : '97.1',  'fix_ver' : '97.1.0.163'},
  {'min_ver' : '96.2',  'fix_ver' : '96.2.0.148'},
  {'min_ver' : '9.8',  'fix_ver' : '9.8.1.6'},
  {'min_ver' : '9.6',  'fix_ver' : '9.6.3.10'},
  {'min_ver' : '9.4',  'fix_ver' : '9.4.4.9'},
  {'min_ver' : '9.2',  'fix_ver' : '9.2.4.23'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['asa_ospf_interface'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCve47393',
  'cmds'     , make_list('show ip ospf interface brief')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
