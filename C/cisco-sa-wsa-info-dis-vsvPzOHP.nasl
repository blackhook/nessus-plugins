#TRUSTED 2c45d0a0a957260a885502c3ad17637c458e83ac081f4cf53c6ae8663e4e64f401d3cdeacfaea1b3aafb2210a1391254dc3e5f9ccecdb1e522e2675537c0bacd7270d04fef412bb1ae87ef8df2efa701631e0210a323dd4f69530ae8b6d93a4230dff4270050a244ef3e9ac37e1bdefac2edd4e76fdad4353e406dfbf6d0285d8b84d30a525830f3cef7e0ff4c3266d2caf130e48e2d938fe207ac11fc31534cf4121651ea53f4c5bf93595472192855c102cc3c6517355814aaf9db8b1a4f9eb53cc9010d24b13c7a5b6305d8f1511a0d41f95b40a314a53287fb30eefd0d5e63e462ffbd7d461d21d70744892603522495abe521a162358921870638485cad5cac57965754b028e5860f161a930f7ede6fa50eb92237f874a9ad4e50e4729f28554036a59a4010dab3ae91c2809ddb9eee04e88f77928d773802159a4c3f43613f54683427ad2f56113d2a3df4e06f2a6cad57066895d38f802ef0a362ca70435fd895a013a6d982f5c4a7cb2272c39b2923b1270b5cb5594b79476f5142c9b55aa40a137660ee5728330b93d9c7cb75a752baebb3788da92d7431925c20c3c3bdd730e2377d528f98a06ba878d99a70501f95c3a89876921af35aa90c36941898a206a54ad52a74d01f6a2c6e41839113fb3e316cac780f48caf8c2049b35b688d9bd2ec64a7858087daaf26aa8160b0ecc54b92e91bd7f83dacd8887ca81
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140404);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/14");

  script_cve_id("CVE-2020-3547");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt98774");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu03264");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu08049");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sma-wsa-esa-info-dis-vsvPzOHP");
  script_xref(name:"IAVA", value:"2020-A-0400-S");

  script_name(english:"Cisco Web Security Appliance (WSA) Information Disclosure (cisco-sa-sma-wsa-esa-info-dis-vsvPzOHP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Web Security Appliance (WSA) is affected by an information disclosure
vulnerability in the web-based management interface of Cisco AsyncOS software due to the use of an insecure method to
mask certain passwords on the web-based management interface. An authenticated, remote attacker could exploit this by 
looking at the raw HTML code that is received from the interface. A successful exploit could allow an attacker to obtain
some of the passwords configured throughout the interface. 

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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

# Cisco WSA Release 12.0.1-268 and earlier
vuln_ranges = [{ 'min_ver' : '0.0' ,'fix_ver' : '11.7.2.011' }];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'fix'      , '11.7.2-011',
  'bug_id'   , 'CSCvt98774, CSCvu03264, CSCvu08049',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);


