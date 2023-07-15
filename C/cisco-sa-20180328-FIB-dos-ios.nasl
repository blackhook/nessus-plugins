#TRUSTED 0995dfd373bb11429c0f257d0f24461aecf3e73919016ff6852fff17f637c2b979405897a4db36b1fc3e746f5a79836c54abe52b5f4294b7b264298ef6d37f7a9edebe4c6c22021c1a047c0b3dacc61306ec8c8ec120ee01bf4f34783eb3376dcf8b0576e9432656c774193dd53ead024ff54d8c956c4f2a85810863a1707d58628bb60435965420c6e93d2c551b360ac23be80be4d71372fd9500a9005bf31d3022e47f9ad18013a599c13e5cd4dfe092aa9bf8c0a785f1ba038d1da895492fe02e2bcf019ba6e72c42a31a9b325c1ca973dcd709a2a1bb4e61562e8023b51c86251556727eea84cb3279920a3f2d9a5d90c06ca52c2ca78b0f6bf9b42f7965cad64891478a49c72b2bc245afe0ac61be66426ad7acde6ab46048e1879b2d1eaa7b21844a3afef02d4d0b15d31817137efa0bc16a5a5c29dcd58e045de19ccfeb957871c769f40212cb002dfb9b2367d2f543184a259d2afac4890abb97f68844a829f0923517bfab6e4ebd2a3cf54a720af9cb6f08e30194028f9bde62b716b3e45e762e53baf553939a5211df0f877495ebd10bcf6b5dfeb9c749245d69e223019317e0603b3e5d3bf7ccf733d8218bb78ad2cb7f016e617dbcd073ea8c301b32c45e5f081b3b4875cc318a76d3d60fe4604966f5570dba3878be9f4ee1eed27b7dac43d343069aacd1b9cb4e8af6dfadc6c65d11e470e0ef38c396cd241c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132697);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2018-0189");
  script_bugtraq_id(103548);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva91655");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-FIB-dos");

  script_name(english:"Cisco IOS Forwarding Information Base DoS (cisco-sa-20180328-FIB-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a denial of service (DoS) vulnerability in the
Forwarding Information Base code due to a limitation in the way the FIB is internally representing recursive routes. An
unauthenticated, network attacker can exploit this, by injecting routes into the routing protocol that have a specific
recursive pattern, provided that the attacker is in a position on the network that provides the ability to inject a
number of recursive routs with a specific pattern. An exploit allows the attacker to cause an affected device to
reload, creating a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-FIB-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9af64740");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva91655");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCva91655.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0189");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS');

# Some further information on versions can be found here:
# https://community.cisco.com/t5/cisco-bug-discussions/cscva91655-cisco-ios-and-ios-xe-software-forwarding-information/m-p/3371988/highlight/false#M7119
if ('E' >< product_info['version'])
{
  vuln_ranges = [
    {'min_ver' : '15.2',  'fix_ver' : '15.2(1)E1'},
    {'min_ver' : '15.2(2)',  'fix_ver' : '15.2(2)E1'},
    {'min_ver' : '15.2(3)',  'fix_ver' : '15.2(4)E5'},
    {'min_ver' : '15.2(5)',  'fix_ver' : '15.2(5)E1'},
  ];
}
else if ('S' >< product_info['version'] && 'Y' >!< product_info['version'])
  vuln_ranges = [
    # 15.4S train has 15.4(1)S0a, 15.4(1)S1 as First Fixed Release, using just 15.4(1)S0a
    {'min_ver' : '15.4',  'fix_ver' : '15.4(1)S0a'},
    {'min_ver' : '15.4(2)',  'fix_ver' : '15.4(2)S1'},
    {'min_ver' : '15.4(3)',  'fix_ver' : '15.4(3)S7'},
    {'min_ver' : '15.5',  'fix_ver' : '15.5(3)S5'},
  ];
else if ('M' >< product_info['version'])
  vuln_ranges = [
    {'min_ver' : '15.5',  'fix_ver' : '15.5(3)M5'}
  ];
else
  audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCva91655',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
