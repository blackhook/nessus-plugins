#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176454);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/29");

  script_name(english:"Atlassian Confluence < 7.19.9 (CONFSERVER-83218)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-83218 advisory. A remote attacker, authenticated with read permissions, can upload attachments despite
not having permissions to due to a broken access control vulnerability in the attachments feature.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-83218");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on an in-depth analysis of the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"all");


  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl", "confluence_nix_installed.nbin", "confluence_win_installed.nbin");
  script_require_keys("installed_sw/Atlassian Confluence");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Atlassian Confluence');

var constraints = [
  { 'min_version': '7.13.0', 'fixed_version' : '7.19.9' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
