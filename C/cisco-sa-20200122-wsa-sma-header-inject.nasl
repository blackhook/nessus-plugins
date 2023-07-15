#TRUSTED 62e096a7e7cd4d6e13ddb7ab11734749a5a139c62d0c8d9d49c519127e64be33319d9ecba66f8014b493e8989b7fc596d23f16170f0ca6738c07911289c9ccddb9d298d20bd3194f8ff9b2cc0c73b010e1c25625d1fe67f177a81e4add6a52842ac99a4662da797b21b27483035a8cc0865e6feba9224aced258fdbef969ca5dbbc30c18dcc192e6b24ce42243c7f5e081d98b2a4ca19eb73c96eff1b8451db66d824b79c189e0b06403ac1f2ea4d711c43a544a743c9f11d453ff27803ae9c126c480afc53b3b2c6938cc4455cd2d3742701693687673b30947ba8c6cb1750e3de894e974c7e5d4214f73bc8b0ec84b9a772e875512b7509e1f0495022da3191cb30a00d2f69ddcd955a9561170c09f2ac18cd830bbff2c062930fc0d862dcc022f1ceb35e66c253f52bcad27a5280f1b41b6d6f0e2ae050e277d209cb52da9c258c48058616ad97c85e91be16f01741422d5c1907a9bcb76b049f4fff21256dffc167b9490792ab1289d3dd88545d4fd92695cf95f93ec81385acd6d2497430f07bcde34a47bab4826e1314c11c8558bda9f22f9a4c31e514f0b9150bf9d964863502a495f221a6236b328ed46cf1d21cefe1feefac05117a0fd9307e56612f794789e6e16a4eaa035b4866e66d24e2d6e196c3492c925e2274d49dff073dcb5e8b01e1f3bdd01bb10a11d0f377cde736a0d50e42ec7cbd13352e1656ca5d1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133406);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/14");

  script_cve_id("CVE-2020-3117");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp16724");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq04931");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200122-wsa-sma-header-inject");
  script_xref(name:"IAVA", value:"2020-A-0045");

  script_name(english:"Cisco Web Security Appliance HTTP Header Injection Vulnerability");
  script_summary(english:"Checks the version of Cisco Web Security Appliance (WSA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Web Security Appliance (WSA) 
is affected by a HTTP Header Injection vulnerability. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200122-wsa-sma-header-inject
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ceb28f0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp16724");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq04931");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security Advisory
cisco-sa-20200122-wsa-sma-header-inject.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3117");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/31");

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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

vuln_ranges = [
  { 'min_ver' : '1.0.0.0' ,'fix_ver' : '11.8.0.382' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvp51493',
'fix'      , '11.8.0-382',
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
