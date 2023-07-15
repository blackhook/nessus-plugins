##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160400);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2021-44228");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa47133");
  script_xref(name:"CISCO-SA", value:"cisco-sa-apache-log4j-qRuKNEbd");
  script_xref(name:"IAVA", value:"2022-A-0138-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/24");
  script_xref(name:"CEA-ID", value:"CEA-2021-0052");
  script_xref(name:"CEA-ID", value:"CEA-2023-0004");

  script_name(english:"Cisco Identity Services Log4j Engine Remote Code Execution (cisco-sa-apache-log4j-qRuKNEbd)");

  script_set_attribute(attribute:"synopsis", value:
"A package installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"Cisco Identity Services Engine is affected by the following critical vulnerability in the Apache Log4j Java 
logging library as descibed in the cisco-sa-apache-log4j-qRuKNEbd advisory.

  - Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log
    messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.
    An attacker who can control log messages or log message parameters can execute arbitrary code loaded from
    LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been
    disabled by default. From version 2.16.0, this functionality has been completely removed. Note that this
    vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging
    Services projects. (CVE-2021-44228)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?395cf983");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa47133");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44228");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}
include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'2.4', 'fix_ver':'2.6.0.156', required_patch:'11'},
  {'min_ver':'2.7', 'fix_ver':'2.7.0.356', required_patch:'7'},
  {'min_ver':'3.0', 'fix_ver':'3.0.0.458', required_patch:'5'},
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'1'}
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwa47133',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
