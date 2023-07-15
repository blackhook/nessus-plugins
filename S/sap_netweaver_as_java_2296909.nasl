#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154919);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2016-9563");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"SAP NetWeaver AS Java XXE Vulnerability (2296909)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver AS Java server may be affected by an XML external entity vulnerability");
  script_set_attribute(attribute:"description", value:
"An XML external entity (XXE) vulnerability exists in BC-BMT-BPM-DSK in SAP NetWeaver AS JAVA 7.5. An authenticated, 
remote attacker can exploit this, to conduct XML External Entity (XXE) attacks via the 
sap.com~tc~bpem~him~uwlconn~provider~web/bpemuwlconn URI, aka SAP Security Note 2296909.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/2296909");
  # https://erpscan.io/advisories/erpscan-16-034-sap-netweaver-java-xxe-vulnerability-bc-bmt-bpm-dsk-component/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71f5e865");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9563");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('http.inc');
include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app = 'SAP Netweaver Application Server (AS)';

get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

var constraints = [ {'equal' : '7.50', 'fixed_display' : 'See vendor advisory' } ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);