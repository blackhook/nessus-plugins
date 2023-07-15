#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171502);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/22");

  script_cve_id(
    "CVE-2023-23853",
    "CVE-2023-23854",
    "CVE-2023-23858",
    "CVE-2023-23859",
    "CVE-2023-23860",
    "CVE-2023-24521",
    "CVE-2023-24522",
    "CVE-2023-24529",
    "CVE-2023-25614"
  );
  script_xref(name:"IAVA", value:"2023-A-0076");

  script_name(english:"SAP NetWeaver AS ABAP Multiple Vulnerabilities (Feb 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver ABAP server may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"SAP NetWeaver Application Server for ABAP and ABAP Platform is affected by multiple vulnerabilities, including the
following:

  - SAP NetWeaver AS for ABAP and ABAP Platform - versions 740, 750, 751, 752, 753, 754, 755, 756, 757, 789,
    790, allows an unauthenticated attacker to craft a malicious link, which when clicked by an unsuspecting
    user, can be used to read or modify some sensitive information. (CVE-2023-23859)

  - SAP NetWeaver AS for ABAP and ABAP Platform - versions 740, 750, 751, 752, 753, 754, 755, 756, 757, 789,
    790, allows an unauthenticated attacker to craft a link, which when clicked by an unsuspecting user can be
    used to redirect a user to a malicious site which could read or modify some sensitive information or
    expose the victim to a phishing attack. (CVE-2023-23860)

  - An unauthenticated attacker in AP NetWeaver Application Server for ABAP and ABAP Platform - versions 700,
    702, 731, 740, 750, 751, 752, 753, 754, 755, 756, 757, 789, 790, can craft a link which when clicked by an
    unsuspecting user can be used to redirect a user to a malicious site which could read or modify some
    sensitive information or expose the victim to a phishing attack. Vulnerability has no direct impact on
    availability. (CVE-2023-23853)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18f404d5");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3268959");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3271227");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3282663");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3293786");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3274585");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3269151");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3269118");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3287291");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25614");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('vcf_extras_sap.inc');

var app_info = vcf::sap_netweaver_as::get_app_info();

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var fix = 'See vendor advisory';
var constraints = [
    {'equal' : '700', 'fixed_display' : fix },
    {'equal' : '701', 'fixed_display' : fix },
    {'equal' : '702', 'fixed_display' : fix },
    {'equal' : '731', 'fixed_display' : fix },
    {'equal' : '740', 'fixed_display' : fix },
    {'equal' : '750', 'fixed_display' : fix },
    {'equal' : '751', 'fixed_display' : fix },
    {'equal' : '752', 'fixed_display' : fix },
    {'equal' : '753', 'fixed_display' : fix },
    {'equal' : '754', 'fixed_display' : fix },
    {'equal' : '755', 'fixed_display' : fix },
    {'equal' : '756', 'fixed_display' : fix },
    {'equal' : '757', 'fixed_display' : fix },
    {'equal' : '75C', 'fixed_display' : fix },
    {'equal' : '75D', 'fixed_display' : fix },
    {'equal' : '75E', 'fixed_display' : fix },
    {'equal' : '75F', 'fixed_display' : fix },
    {'equal' : '75G', 'fixed_display' : fix },
    {'equal' : '75H', 'fixed_display' : fix },
    {'equal' : '789', 'fixed_display' : fix },
    {'equal' : '790', 'fixed_display' : fix },
    {'equal' : '804', 'fixed_display' : fix }
  ];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  abap:TRUE,
  flags:{'xss':TRUE}
);
