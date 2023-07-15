#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173431);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/28");

  script_cve_id("CVE-2023-20025", "CVE-2023-20026", "CVE-2023-20118");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd47551");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd60199");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe41652");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sbr042-multi-vuln-ej76Pke5");

  script_name(english:"Cisco Small Business Routers Multiple Vulnerabilities (cisco-sa-sbr042-multi-vuln-ej76Pke5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is out of support and affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to it's reported model number, the remote device is a Cisco Small Business Router model RV016, RV042,
RV042G, RV082, RV320, or RV325. It is, therefore no longer supported and affected by multiple vulnerabilities:

  - A vulnerability in the web-based management interface of Cisco Small Business Routers could allow an 
    unauthenticated, remote attacker to bypass authentication on the affected device. This vulnerability is
    due to incorrect user input validation of incoming HTTP packets. An attacker could exploit this
    vulnerability by sending crafted requests to the web-based management interface. A successful exploit
    could allow the attacker to gain root privileges on the affected device. (CVE-2023-20025)

  - A vulnerability in the web-based management interface of Cisco Small Business Routers could allow an
    authenticated, remote attacker to inject arbitrary commands on an affected device. This vulnerability is
    due to improper validation of user input fields within incoming HTTP packets. An attacker could exploit
    this vulnerability by sending a crafted request to the web-based management interface. A successful
    exploit could allow the attacker to execute arbitrary commands on an affected device with root-level
    privileges. To exploit these vulnerabilities, an attacker would need to have valid Administrator
    credentials on the affected device. (CVE-2023-20118, CVE-2023-20026)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sbr042-multi-vuln-ej76Pke5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dee33f02");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd47551");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd60199");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe41652");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwd47551, CSCwd60199, CSCwe41652");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20025");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv016_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv042_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv042g_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv082_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv320_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv325_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv016");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv042");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv042g");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv082");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv320");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv325");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (toupper(product_info['model']) !~ "^RV(016|042G?|082|32[05])")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwd47551, CSCwd60199, CSCwe41652',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);


cisco::security_report_cisco_v2(reporting:reporting);
