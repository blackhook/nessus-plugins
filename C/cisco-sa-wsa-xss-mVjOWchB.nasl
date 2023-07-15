#TRUSTED 96f3e97581bb6ad1b983d3b9f3c068ae98160a0058fc861d03a23a895c8b7e1f0b491ff9525b8318bcfded3888aaac0d85bd0626c3d0e0745bf16aad0b95513ce39584ca9f967398a2654ee9065be4eb4d2f8fba2dfa332853abfba0e074332d12b826b33575e40c1bafd48fd3f4cf653e2b5fb5799d01db4b1804025a3a7db1b7feeaaeefde70f35a4dfbe96a924b0c8cac306f8f43530f5b606819fae167168ceac312bf19693921b4a29fdf556611b651e48888de4215f55e79ea357f90d1736e0cdd7626d28098cf8438f80102e903ce4c2e24200aef7fcc95626fde44d0314392c512b3b96c117050210b48b668958e96455e7c129ef356df09486e5bf672fa0b81714cc3364c56dc4191b56e6990d19703d0c14ab615f0ec1e25b961f5702bff16dd3db98ee2ea3e3403b71d1e27879b606deb7b7ba7098f971750aeb8130ff7d85304d4e76bbe1276727854a7c2c07c9fb7314c5df707e64a251c3924a2f71db5d67a3bd9274ca21c104f230fb7027f86cea9a3163706a8d18ffb04db5b2ef32b51035ca49039679b6b39d11e68e2f23f21c1c50326769597e6adb7e0de2422ae2451df4d153d467b138dac7e021ac14f4d34e54ba4ce75e2abe27e4fa503df7eb4a16e815d7a8c7c0d1837aa05b6ae411ac3c92a5ea0aa9fc9ac54b2b33ad6f4c0fa41dbef20db1fc923af06568a4968a535ebc484fb444332d9af4c
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149450);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2021-1490");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv18456");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv26363");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx74586");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wsa-xss-mVjOWchB");
  script_xref(name:"IAVA", value:"2021-A-0238-S");

  script_name(english:"Cisco Web Security Appliance XSS (cisco-sa-wsa-xss-mVjOWchB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Web Security Appliance is affected by a cross-site scripting (XSS)
vulnerability due to improper validation of user-supplied input before returning it to users. An unauthenticated, remote
attacker can exploit, by convincing a user to click a specially crafted URL, to execute arbitrary script code in a
user's browser session. Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wsa-xss-mVjOWchB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b504e08");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv18456");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv26363");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx74586");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv18456, CSCvv26363, CSCvx74586");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1490");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

var vuln_ranges = [
  { 'min_ver' : '0.0' ,'fix_ver' : '14.0' }
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv18456, CSCvv26363, CSCvx74586',
  'disable_caveat', TRUE,
  'xss'      , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

