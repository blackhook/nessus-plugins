#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177995);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");
  
  script_cve_id("CVE-2023-22503");
  script_xref(name:"IAVA", value:"2023-A-0330");

  script_name(english:"Atlassian Confluence < 7.13.15 / 7.14.x < 7.19.7 / 7.20.x < 8.2.0 (CONFSERVER-82403)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by information disclosure 
vulnerability as referenced in the CONFSERVER-82403 advisory. Affected versions of Atlassian Confluence Server and Data 
Center allow anonymous remote attackers to view the names of attachments and labels in a private Confluence space. This 
occurs via an information disclosure vulnerability in the macro preview feature. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-82403");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.13.15, 7.19.7, 8.2.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl", "confluence_win_installed.nbin", "confluence_nix_installed.nbin");
  script_require_keys("installed_sw/confluence", "installed_sw/Atlassian Confluence");
  script_require_ports("Services/www", 8080, 8090);

  exit(0);
}


include('vcf.inc');

var app_info =vcf::combined_get_app_info(app:'confluence');

var constraints = [
  { 'min_version' : '0.0.0', 'fixed_version' : '7.13.15' },
  { 'min_version' : '7.14.0', 'fixed_version' : '7.19.7' },
  { 'min_version' : '7.20.0', 'fixed_version' : '8.2.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
