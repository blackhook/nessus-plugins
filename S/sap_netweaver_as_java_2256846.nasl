##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162316);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2016-2388");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/30");

  script_name(english:"SAP NetWeaver AS Java Information Disclosure (2256846)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver AS Java server may be affected by a information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Universal Worklist Configuration in SAP NetWeaver AS JAVA 7.1 to 7.5, allows remote attackers to obtain sensitive 
user information via a crafted HTTP request, aka SAP Security Note 2256846.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://erpscan.io/advisories/erpscan-16-010-sap-netweaver-7-4-information-disclosure/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?385b1f7d");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/2256846");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2016/May/55");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2388");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('vcf_extras_sap.inc');

var app_info = vcf::sap_netweaver_as::get_app_info();

var constraints = [ {'min_version' : '7.1', 'max_version' : '7.5', 'fixed_display' : 'See vendor advisory' },
];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
