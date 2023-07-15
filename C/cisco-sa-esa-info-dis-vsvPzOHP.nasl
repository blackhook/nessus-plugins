#TRUSTED 16f885593c2cba4d242bb126e6c0e1e460ac423d5032171c2fc99ddd98759ad6ad30a669be5985791caf10bcf1227046f1bb08746be46721aba2a4f0de548f803d247839c05f3d4bdca319ab629d00ba500954d0385dc1077f2b208ca27481a0b14129ad95e8be90ba5b4eb4a5587b55e6f7a503d22aabf5da42963396a2d807433afee76848a8314b2ba3c0286719cd86840290311032f05d1e9fd7f11e6b603d5b45bc952d0e39dfeb68577235e3d55426ab7eba6a0f632013c3b9daae73a424af294d8b25c340b42a41526eabd1be14ecdfd2910ca6416327c4bc2255bf566053e16299be72422826c32b00e8b46699cebdd08685411bb136fb9381b3e6c910952340cb417805ade6f049578710bd92da96c781e52afc27cded75a821e584ad6d61f9153c8d04dc9a095d920884daab5baa4f3a5657d59d1bd214985f255291d64f0d6d1b71ea7bf3dc616bffe9282e75fb7136e5123fba0c107d0c15d3a816b91238b2573ff8632977b78cad3282be84207314aa6bd2fc3d3343ce7878bad66ae592decabea8d66f819db243df11e8fec5492988c83cd051d2690fcdae60a5560dbf022e2098f91f500a6b0319e9682723ec3ace521b1e85e71cc2536679a77f9fb56c0c610b30e62b98dd7265138820c8d5954aaf24b6e9b4e2914ecf897b8e3d5c1c2dcd141d1ccf4bb0721c9a7d18b9025abb982a54cd4127acc9a6c9
#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020/10/27 because Cisco ESA is no longer affected by CVE-2020-3547.

include('compat.inc');

if (description)
{
  script_id(140402);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3547");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt98774");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu03264");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu08049");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sma-wsa-esa-info-dis-vsvPzOHP");
  script_xref(name:"IAVA", value:"2020-A-0400-S");

  script_name(english:"Cisco Email Security Appliance (ESA) Information Disclosure (cisco-sa-sma-wsa-esa-info-dis-vsvPzOHP)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Email Security Appliance (ESA) is affected by an information
disclosure vulnerability in the web-based management interface of Cisco AsyncOS software due to the use of an insecure 
method to mask certain passwords on the web-based management interface. An authenticated, remote attacker could exploit
this by looking at the raw HTML code that is received from the interface. A successful exploit could allow an attacker
to obtain some of the passwords configured throughout the interface. 

Please see the included Cisco BIDs and the Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sma-wsa-esa-info-dis-vsvPzOHP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d6cbaf0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt98774");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu03264");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu08049");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3547");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Cisco ESA is no longer affected by CVE-2020-3547. Refer Cisco advisory for more information.");


include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

# Cisco ESA 13.0.0-392 and earlier
vuln_ranges = [{ 'min_ver' : '0.0', 'fix_ver' : '13.5.1.277' }];

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvt98774, CSCvu03264, CSCvu08049',
  'fix'           , '13.5.1-277',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);


