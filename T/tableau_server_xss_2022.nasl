#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170978);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");
  script_xref(name:"IAVB", value:"2022-B-0053-S");


  script_name(english:"Tableau Server Input Validation XSS");

  script_set_attribute(attribute:"synopsis", value:
"A Tableau Server instance installed on the remote host is affected by a XSS vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Tableau running on the remote host is affected by an XSS vulnerability that could allow malicious 
actors to extract sensitive data from the application. An attacker could leverage the cross-site scripting 
vulnerability to conduct an attack against a user and gain access to sensitive information. It could also lead to 
account takeover using a malicious login page or vertical privilege escalation by sending requests to add a malicious 
user as administrator on the application.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.gosecure.net/blog/2022/07/13/tableau-server-leaks-sensitive-information-from-reflected-xss/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e424519");
  script_set_attribute(attribute:"solution", value:
"Upgrade Tableau Server to 2020.4.16, 2021.1.13, 2021.2.10, 2021.3.9, 2021.4.5 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tableau:tableau_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tableau_server_web_detect.nbin");
  script_require_keys("installed_sw/Tableau Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Tableau Server');

var constraints = [
  { 'min_version' : '0.0',    'fixed_version' : '2020.4.16' },
  { 'min_version' : '2021.1',    'fixed_version' : '2021.1.13' },
  { 'min_version' : '2021.2',    'fixed_version' : '2021.2.10' },
  { 'min_version' : '2021.3',    'fixed_version' : '2021.3.9' },
  { 'min_version' : '2021.4',    'fixed_version' : '2021.4.5' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  flags:{xss:TRUE},
  severity:SECURITY_HOLE
);