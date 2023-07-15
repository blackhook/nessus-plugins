#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140504);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/20");

  script_cve_id("CVE-2020-6313", "CVE-2020-6326");
  script_xref(name:"IAVA", value:"2020-A-0421");

  script_name(english:"SAP NetWeaver AS Java Multiple XSS (2953112)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver AS Java server may be affected by cross-site scripting vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of SAP NetWeaver AS Java detected on the remote host may be affected by multiple cross-site scripting
vulnerabilities, as follows:

  - SAP NetWeaver Application Server JAVA (XML Forms) versions 7.30, 7.31, 7.40, 7.50 does not sufficiently
    encode user controlled inputs, which allows an authenticated User with special roles to store malicious
    content, that when accessed by a victim, can perform malicious actions by executing JavaScript, leading
    to Stored Cross-Site Scripting. (CVE-2020-6313)

  - SAP NetWeaver (Knowledge Management), version-7.30,7.31,7.40,7.50, allows an authenticated attacker to
    create malicious links in the UI, when clicked by victim, will execute arbitrary java scripts thus extracting or modifying information otherwise restricted leading to Stored Cross Site Scripting. (CVE-2020-6326)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.scn.sap.com/wiki/pages/viewpage.action?pageId=557449700");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/2953112");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6313");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('http.inc');
include('vcf.inc');

app = 'SAP Netweaver Application Server (AS)';

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  {'min_version' : '7.30', 'fixed_version' : '7.53', 'fixed_display' : 'See vendor advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
