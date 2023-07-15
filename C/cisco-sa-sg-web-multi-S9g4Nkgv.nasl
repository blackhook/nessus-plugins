#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176111);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/22");

  script_cve_id(
    "CVE-2023-20024",
    "CVE-2023-20156",
    "CVE-2023-20157",
    "CVE-2023-20158",
    "CVE-2023-20159",
    "CVE-2023-20160",
    "CVE-2023-20161",
    "CVE-2023-20162",
    "CVE-2023-20189"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe27386");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe27393");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe27394");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe27403");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe27424");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe27425");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe27441");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe27444");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe27445");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe32312");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe32313");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe32315");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe32318");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe32321");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe32323");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe32326");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe32334");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe32338");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sg-web-multi-S9g4Nkgv");
  script_xref(name:"IAVA", value:"2023-A-0262");

  script_name(english:"Cisco Small Business Series Switches Buffer Overflow Vulnerabilities (cisco-sa-sg-web-multi-S9g4Nkgv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities in the web-based user interface of certain Cisco Small Business Series Switches could allow
an unauthenticated, remote attacker to cause a denial of service (DoS) condition or execute arbitrary code with root
privileges on an affected device. These vulnerabilities are due to improper validation of requests that are sent to
the web interface.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sg-web-multi-S9g4Nkgv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?618cd4e4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe27386");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe27393");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe27394");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe27403");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe27424");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe27425");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe27441");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe27444");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe27445");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe32312");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe32313");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe32315");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe32318");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe32321");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe32323");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe32326");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe32334");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe32338");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe27386, CSCwe27393, CSCwe27394, CSCwe27403,
CSCwe27424, CSCwe27425, CSCwe27441, CSCwe27444, CSCwe27445, CSCwe32312, CSCwe32313, CSCwe32315, CSCwe32318, CSCwe32321,
CSCwe32323, CSCwe32326, CSCwe32334, CSCwe32338");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20189");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_series_switch");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:small_business_series_switch");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_switch_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);
var app_info = vcf::get_app_info(app:'Cisco Small Business Series Switch', port:port, webapp:TRUE);

# 250 Series Smart Switches
# 350 Series Managed Switches
# 350X Series Stackable Managed Switches
# 550X Series Stackable Managed Switches
if (app_info['model'] !~ "^CBS(2|3)50")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business Series switch');

var constraints = [ {'min_version':'0.0', 'fixed_version' : '3.3.0.16'} ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);