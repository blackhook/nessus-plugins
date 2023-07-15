##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163081);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-20859");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz16246");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ucm-access-dMKvV2DY");
  script_xref(name:"IAVA", value:"2022-A-0266");

  script_name(english:"Cisco Unified Communications Manager Improper Access Control (cisco-sa-ucm-access-dMKvV2DY)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Unified Communications Manager installed on the remote host is 14.x prior to 14SU2. It is,
therefore, affected by an improper access control vulnerability. An authenticated attacker with read-only privileges
can exploit this vulnerability to perform a set of administrative actions they should not be able to.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucm-access-dMKvV2DY
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?997ee628");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz16246");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz16246");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20859");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

# https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/14_0_1/SU2/cucm_b_release-notes-for-cucm-imp-14su2.html
var vuln_ranges = [{ 'min_ver' : '14.0',  'fix_ver' : '14.0.1.12900.161'}];

var reporting = make_array(
  'port', 0,
  'severity', SECURITY_HOLE,
  'version', product_info['display_version'],
  'bug_id', 'CSCvz16246',
  'fix', '14SU2',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
