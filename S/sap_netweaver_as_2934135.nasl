#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138506);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-6286", "CVE-2020-6287");
  script_xref(name:"IAVA", value:"2020-A-0298");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0058");

  script_name(english:"SAP NetWeaver AS Java Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver AS Java server may be affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of SAP NetWeaver AS Java detected on the remote host may be affected by multiple vulnerabilities,
as referenced in SAP Security Note 2934135.

- LM Configuration Wizard of SAP NetWeaver AS JAVA, does not perform an authentication check which 
allows an attacker without prior authentication, to execute configuration tasks to perform critical 
actions against the SAP Java system, including the ability to create an administrative user, 
and therefore compromising Confidentiality, Integrity and Availability of the system (CVE-2020-6287).

- The insufficient input path validation of certain parameter in the web service, allows an unauthenticated 
attacker to exploit a method to download zip files to a specific directory (CVE-2020-6286).


Note that Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number.");
  # https://wiki.scn.sap.com/wiki/pages/viewpage.action?pageId=552599675
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a89e2685");
  # https://launchpad.support.sap.com/#/notes/2934135
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff519fdb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6287");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('install_func.inc');
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

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
