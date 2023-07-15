##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161813);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2021-44228");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa47288");
  script_xref(name:"CISCO-SA", value:"cisco-sa-apache-log4j-qRuKNEbd");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/24");
  script_xref(name:"CEA-ID", value:"CEA-2021-0052");
  script_xref(name:"CEA-ID", value:"CEA-2023-0004");

  script_name(english:"Cisco UCS Director Log4j Remote Code Execution (cisco-sa-apache-log4j-qRuKNEbd)");

  script_set_attribute(attribute:"synopsis", value:
"A package installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"Cisco UCS Director is affected by the following critical vulnerability in the Apache Log4j Java logging library
  as described in the cisco-sa-apache-log4j-qRuKNEbd advisory.
  
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
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa47288");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa47288");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:ucs_director");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucs_director_detect.nbin");
  script_require_keys("Host/Cisco/UCSDirector/version");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco UCS Director', kb_ver:'Host/Cisco/UCSDirector/version');

# UCS Director earlier than 6.8.2.0
constraints = [
  { 'fixed_version': '6.8.2.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
