#TRUSTED 1e1a42f5d60281780b3b7a80769e2b91e3bfdd7fd44f4a192b0ceaf4c60833cd776761ade1b72702da18cc04b5abef6566972de85394b3452cec977f5fe353980dc56b2eb63c2aaa7743914da87e8997d3ec277a8e3f9ddab99ae9d4c4149672b4fddd043a95285d67a37b58fa709e802ef3a7dee7969ca00e1465fbfde6b113ec7fccf77b49117b4ab984cff72d4a28b7e572500627d39d2297544c37ef127bff8d7ed566a832ce0ba6840e0c194b92e92ad7d54b9d212c129e19dc23e0e5a091301038ebce246b10f77eb6ec7042f3a623b87ff7ef133f8a99a462b1af54dc0fc1c6c9bb1f3994dc7b7e70809c49be3e5090ca8cdfe03b5586470478d3bfabdf8682e9f65d4539eaf2e688fbfe22d6a6093bcad3f6b5dba34b9f51711e814ec85a1069d1a9614d8dd3087d3dc50a7c86021dd1e765b9e84e34435e840dbbbed3294166fbc3a5b7fd98a4e9e7e099d974bbe89360b59944368d08c0176fd904387685404ad6f25fdca80f45e2688ca89bfd95ce8a13f1a980c61bb4b102ddf7d706456d6e93102a88200d2f44bbb5a53c5eea6b1a32f47aa3c58732e87f3b4cd8c399bbfea6be86c31515eefb837c460f861d642b17918047115b27e80487444da45afa433d4ce392ddc7d419e5f129afc7d54bfee8bc6d69f1105e3e1004ab6ac305def2c6743132e411527bebaf310c8103c13972147a46afcaadabe739bd
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129813);
  script_version("1.7");
  script_cvs_date("Date: 2020/01/17");

  script_cve_id("CVE-2019-12695");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp33341");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-asa-xss");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco Adaptive Security Appliance WebVPN XSS (cisco-sa-20191002-asa-xss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Clientless SSL VPN (WebVPN) portal of Cisco Adaptive Security Appliance (ASA) allows an
unauthenticated, remote attacker to conduct a cross-site scripting (XSS) attack against a user of the web-based
management interface of an affected device. The vulnerability is due to insufficient validation of user-supplied input
by the web-based management interface of an affected device. An attacker can this vulnerability by persuading a user of
the interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code
in the context of the interface or allow the attacker to access sensitive browser-based information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-asa-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf358a6d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp33341");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp33341");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '9.6.4.31'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8.4.9'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9.2.56'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.30'},
  {'min_ver' : '9.12',  'fix_ver' : '9.12.2.9'},
  {'min_ver' : '9.13',  'fix_ver' : '9.13.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['ssl_vpn']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp33341',
  'cmds'     , make_list('show running-config'),
  'xss'      , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
