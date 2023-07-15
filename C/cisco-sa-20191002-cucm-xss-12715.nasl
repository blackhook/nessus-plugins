#TRUSTED 30e343740111b8c73d0e26ce04c434fa5b61854e15dce83462b1f36542b3d00cd595497341ece890b6dcdeb786165ce41d501cf431430c5742dbd3f96c04e070966ef207a4be0c67d8e317f979d3ff039f6d59d61384905fdf02a66f3402460dce39bd8cb6f35ac9726086ec5c3e1a420e71993c2811beac39765ff404a6d0db65b37bbf20c9c889db76a1ba8dcb96b6b7845572f895a536d37434475659a2305ad0c569a93dad9e2eb27d2e9499fc979cd15d8821eb29b7ef9a0ea89cd5925ccae2e9eb0c4e40e4e64ed5211287f55afd5b05337e48095edfdad18bd4643339b8031bdae5ac657c646b0f8d0e3f34deac54a41792d234976e7c4ba3e69a3f50540ee58ee2cee016541942a3b48ec54eeead10767e91ceabfc40d982df296f21d6a5763c4d4978c55e6647c271cc1725f3e8833df5c4304891452e53b0ac19717ff43fba4c7b14e1cb78d2724013894d5db8d334c8e3326f7a7f4bd8b8cd225fc98d8f9770eec6ddb20cf0feb71e395e7a4301d556555ad125371066fb8b83f13221f9d1a1035b4813bbe1c930f109c25b4313c63b0641eba405de5d087f8f68fea723e4cb3cce82afc84bab01266f03bfa25e89d10d87ef38a0c07fe9329ea69dedc9f2781d06bd06575f8296092ed630c6a303438663d93c2065320723a9fe4afe835c8fe2dd3b72e967e2c4fca162a247304d188086cada8948c897a85297
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130213);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-12715");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo42294");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-cucm-xss-12715");
  script_xref(name:"IAVA", value:"2019-A-0362");

  script_name(english:"Cisco Unified Communications Manager Cross-Site Scripting (XSS) Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager is affected by a cross-site scripting 
(XSS) vulnerability due to improper validation of user-supplied input before returning it to users. An unauthenticated,
remote attacker can exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script 
code in a user's browser session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-cucm-xss-12715
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05bd0dbd");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo42294
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47b9e792");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID 
  CSCvo42294");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12715");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '10.5.2.21900.13'},
  {'min_ver' : '11.5', 'fix_ver' : '11.5.1.16900.16'},
  {'min_ver' : '12.0', 'fix_ver' : '12.0.1.23900.9'},
  {'min_ver' : '12.5', 'fix_ver' : '12.5.1.11900.146'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo42294'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
