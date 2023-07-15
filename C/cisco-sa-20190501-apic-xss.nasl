#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134213);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/05");

  script_cve_id("CVE-2019-1838");
  script_bugtraq_id(108169);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo76562");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-apic-xss");
  script_xref(name:"IAVA", value:"2019-A-0219-S");

  script_name(english:"Cisco Application Policy Infrastructure Controller Web-Based Management Interface Cross-Site Scripting Vulnerability (cisco-sa-20190501-apic-xss)");
  script_summary(english:"Checks the version of Cisco Application Policy Infrastructure Controller (APIC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Application Policy
Infrastructure Controller (APIC) is affected by following
vulnerability

  - A vulnerability in the web-based management interface of
    Cisco Application Policy Infrastructure Controller
    (APIC) could allow an authenticated, remote attacker to
    conduct a cross-site scripting (XSS) attack against a
    user of the web-based management interface of an
    affected device.The vulnerability is due to insufficient
    validation of user-supplied input by the web-based
    management interface. An attacker could exploit this
    vulnerability by persuading a user of the interface to
    click a crafted link. A successful exploit could allow
    the attacker to execute arbitrary script code in the
    context of the affected interface or access sensitive,
    browser-based information. (CVE-2019-1838)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-apic-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56098080");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo76562");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvo76562");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1838");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:application_policy_infrastructure_controller_apic");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("http.inc");
include("ccf.inc");

port = get_http_port(default:443);
product_info = cisco::get_product_info(name:'Cisco APIC Software', port:port);

version_list=make_list(
  '3.2(5d)',
  '4.0(3d)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo76562',
  'xss'      , true,
  'disable_caveat'   , true
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
