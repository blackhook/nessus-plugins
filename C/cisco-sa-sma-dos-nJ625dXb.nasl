#TRUSTED 3f8036dfa184414a0645b494570d95404d713b7e0492175c5d178529a67a23893af48fb6c9fc1577f2a83d493e5923d8736121d8e84fef8436ee48f87697cfc8632fc743b8c9d3dfa19a88968f57e5692cf12f4d16c8d34ee67e938ce1e20df3dcbfa7374ddcb7bbab2c7d3a3987339285f50139afd71c7e03957d8fab2512da54ff71351c1ed19ea62d3fe60662f87425c2797caaf1798f83ea0a1243da85d8ee45aff8f1b30b9a458e4ab6e5f4c684c8440de9b3042f480511020fe8c0d500dbcab748126b1247d2e2a71f5b97ccf17b6fe1e62280084ce104e166fe303fac5e6403349fcd1114f798773df57e494f478c733b30052efc4f1b7396372c560030b895ba9e00ea77ea562e55adc8f66bd189ea0b2a987e93492fe067a20bfb419510eb98d670e51028aa037af0bf6069bcfa7754a2727373a433dfea44852d0bf2721da3e33d2c548a93648529320bae05de8ad1deb47cc0d0e90a0891eac920587ef5d834f9d9cba5c3a37f8a06f1e1bb44d34b2b1380568357f7fc027437266a45365db6ed8129f8e01a9b00328d093e306f31b660beab1ae8b5066f87a6edaf98fb33f636a62d286698e0cc1d5f12136ecd693959eefbcd108046ed3b1ccdba21a2edc6b54764eeee08a28eeeee3a211800f1c8dadc9dc08d82489f1c16e8d777b4775410aa6d14db7fe31fd4b5e2a63e4a863816a4664ebb615d86c8fd64
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134445);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3164");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq96943");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs33296");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs33306");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cont-sec-gui-dos-nJ625dXb");
  script_xref(name:"IAVA", value:"2020-A-0100");

  script_name(english:"Cisco Content Security Management Appliance (SMA) GUI Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Content Security Management Appliance (SMA) is affected by a Denial
of Service vulnerability. The vulnerability is due to improper validation of specific HTTP request headers. An attacker
could exploit this vulnerability by sending a malformed HTTP request to an affected device. A successful exploit could
allow the attacker to trigger a prolonged status of high CPU utilization relative to the GUI process(es).

Please see the included Cisco BIDs and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cont-sec-gui-dos-nJ625dXb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bded73ef");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq96943");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs33296");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs33306");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security Advisory
cisco-sa-cont-sec-gui-dos-nJ625dXb.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3164");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco Content Security Management Appliance (SMA)");

#Cisco SMA releases earlier than 13.6.0
vuln_list = [{'min_ver' : '0.0' , 'fix_ver' : '13.6.0'}];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'fix'      , '13.6.0',
  'bug_id'   , 'CSCvq96943',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_list
);