##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161213);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2021-44228");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa46525");
  script_xref(name:"CISCO-SA", value:"cisco-sa-apache-log4j-qRuKNEbd");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/24");
  script_xref(name:"CEA-ID", value:"CEA-2021-0052");
  script_xref(name:"CEA-ID", value:"CEA-2023-0004");

  script_name(english:"Cisco Unified Intelligence Center Log4j RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Intelligence Center is affected by a remote code execution
vulnerability.

  - Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI
    features used in configuration, log messages, and parameters do not protect against attacker controlled
    LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters
    can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From
    log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3,
    and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to
    log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.
    (CVE-2021-44228)

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?395cf983");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa46525");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID CSCwa46525.");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_intelligence_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_voss_cuic_installed.nbin");
  script_require_keys("installed_sw/Cisco Unified Intelligence Center (CUIC)", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:'Cisco Unified Intelligence Center (CUIC)');

# known affected releases: 12.6(1), 12.6(1)ES01, 12.6(1)ES02, 12.6(2), version format is x.x.x.10000-xx
constraints = [
  { 'min_version':'12.6.1', 'fixed_version':'12.6.3', 'fixed_display':'Bug ID: CSCwa46525' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
