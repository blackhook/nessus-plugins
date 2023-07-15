#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172406);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2023-20064");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz42457");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc97332");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd61802");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd61820");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd79460");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-load-infodisc-9rdOr5Fq");
  script_xref(name:"IAVA", value:"2023-A-0126");

  script_name(english:"Cisco IOS XR Software Bootloader Unauthenticated Information Disclosure (cisco-sa-iosxr-load-infodisc-9rdOr5Fq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by an information disclosure vulnerability. An
unauthenticated attacker with physical access can exploit this, by being connected to the console port when the device
is power cycled, in order to view sensitive files.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-load-infodisc-9rdOr5Fq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f345cc3");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74917
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6d11e40");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz42457");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc97332");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd61802");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd61820");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd79460");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz42457, CSCwc97332, CSCwd61802, CSCwd61820,
CSCwd79460");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20064");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info.model);
var vuln_model = FALSE;

# Vulnerable model list
if ('ASR9K' >< model)
{
  # https://community.cisco.com/t5/service-providers-knowledge-base/ios-xr-release-strategy-and-deployment-suggestion/ta-p/3165422#toc-hId--1890557219
  if (ver_compare(fix:'7.0', ver:product_info['version'], strict:FALSE) >= 0) # ASR9k 7.0+ is all 64 bit, so vuln
    vuln_model = TRUE;
  else if (ver_compare(fix:'6.1.2', ver:product_info['version'], strict:FALSE) < 0) # ASR9k < 6.1.2 is all 32bit, not vuln
    vuln_model = FALSE;
  else if (report_paranoia >= 2) # flag the rest of the ASR9K with paranoia
    vuln_model = TRUE;
  else
    audit(AUDIT_POTENTIAL_VULN);
}
if ('IOSXRWBD' >< model) # Not seen in detection, guessing
  vuln_model = TRUE;
if ('IOS-XRV 9000' >< model) # Seen in lab
  vuln_model = TRUE;
if (model =~ "NCS-(540|560|1001|1002|1004|5000|5500|5700)([^0-9]|$)") # NCS-540, NCS-5500 seen in output
  vuln_model = TRUE;

if (!vuln_model)
    audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '7.9.1'}
];

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz42457, CSCwc97332, CSCwd61802, CSCwd61820, CSCwd79460',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
