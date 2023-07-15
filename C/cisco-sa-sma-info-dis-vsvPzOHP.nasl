#TRUSTED a963c75d44cc38a665d579240b5d049ceb4e7ba0c9e70c1d7183be951e8c8b94594583d9546913b1845b74a87e42449eb81e61874e6d23409cc6f5cfdfe403feccebc3d4796e2110ab858bae89c9359d57b70a24d47bd5dda98c8a156417c3fe19b09c0056325d75dcdc0707332d16d50dbe9ef657794987fbe5b691865ba91f74312bb0e39903df56592579ca2176eef04a0522305d79a27e16edf7324dfc301e690cc186fade88291f0f7c3c450b32e6359097c298eaaf30ed35b9f003fff6b859118f9a99b797ffb30ac5c92d8cd695d662b2ef427aab2ba800645d978b4008414cda43a3808dd41bb1d1a42e7fbdcc14ac546e52fd6331cc18b400e1934804bd4af63a58c9401fe971d2e5c4577f84d5d72cd2542216e14b516c67b4169496272bc0e0eaacd44fd81db055fa2a5e60fc69d925a052a9bb4edcfa22a50285c1c0fa9ec8f4915dd4e2c9a37979835744c5a07b4e0317b8b5d6e4f6762a1409d3e8d5a6fe089d4e4feabb5bb9e24254c546c3554e2b535b0f7dd32b17d96a9c16696d454a7e8d61476da787b7dc020cf8c9e3c69d06a494214cb7333a61606a7bc0f30ea208945504bab6136b50821bcfdbc509a7056163b6ffcdb328cf220e76e1cf6d0213cd6e29a1fd2ad188a1b0fff2af48f5d513587c8d7627462812e87e3883825c69f9e4cf4e4f611d2cd41b6ec10444287ee2f0143725535c631d76
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140403);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3547");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt98774");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu03264");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu08049");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sma-wsa-esa-info-dis-vsvPzOHP");
  script_xref(name:"IAVA", value:"2020-A-0400-S");

  script_name(english:"Cisco Content Security Management Appliance (SMA) Information Disclosure (cisco-sa-sma-wsa-esa-info-dis-vsvPzOHP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Content Security Management Appliance (SMA) is affected by an
information disclosure vulnerability in the web-based management interface of Cisco AsyncOS software due to the use of
an insecure method to mask certain passwords on the web-based management interface. An authenticated, remote attacker
could exploit this by looking at the raw HTML code that is received from the interface. A successful exploit could allow
an attacker to obtain some of the passwords configured throughout the interface. 

Please see the included Cisco BIDs and the Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sma-wsa-esa-info-dis-vsvPzOHP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d6cbaf0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt98774");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu03264");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu08049");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security Advisory cisco-sa-sma-wsa-esa-info-dis-vsvPzOHP");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3547");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco Content Security Management Appliance (SMA)");

#Cisco SMA releases earlier than 13.6.0
vuln_list = [{'min_ver' : '0.0' , 'fix_ver' : '13.6.1.193'}];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'fix'      , '13.6.1.193',
  'bug_id'   , 'CSCvt98774, CSCvu03264, CSCvu08049',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_list
);


