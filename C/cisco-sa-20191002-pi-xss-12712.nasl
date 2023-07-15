#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140191);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/03");

  script_cve_id("CVE-2019-12712");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp97223");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq12720");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq12740");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq12748");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq12800");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq14464");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq41789");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-pi-xss-12712");

  script_name(english:"Cisco Prime Infrastructure Cross-Site Scripting (cisco-sa-20191002-pi-xss-12712) ");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Prime Infrastructure is affected by a cross-site scripting vulnerability.
The vulnerability is due to insufficient validation of user-supplied input in multiple sections of the web-based
management interface of the affected software. An attacker could exploit this vulnerability by persuading a user of the
interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the
context of the affected interface or access sensitive browser-based information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-pi-xss-12712
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3902ad01");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp97223");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq12720");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq12740");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq12748");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq12800");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq14464");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq41789");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvp97223, CSCvq12720, CSCvq12740, CSCvq12748,
CSCvq12800, CSCvq14464, CSCvq41789");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12712");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_infrastructure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_infrastructure_detect.nbin");
  script_require_keys("installed_sw/Prime Infrastructure");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

port = get_http_port(default:443);
app_info = vcf::get_app_info(app:'Prime Infrastructure', port:port, webapp:TRUE);

constraints = [
  {'fixed_version':'3.7'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
