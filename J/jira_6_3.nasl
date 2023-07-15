#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100220);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-5983");
  script_bugtraq_id(97379);
  script_xref(name:"CERT", value:"307983");

  script_name(english:"Atlassian JIRA 4.2.4 < 6.3.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of
Atlassian JIRA hosted on the remote web server is 4.2.4 or later but
prior to 6.3.0. It is, therefore, affected by multiple vulnerabilities
in the JIRA Workflow Designer plugin :

  - A remote code execution vulnerability exists in the
    Action Message Format (AMF3) deserializer due to
    deriving class instances from java.io.Externalizable
    rather than the AMF3 specification's recommendation of
    flash.utils.IExternalizable. An unauthenticated, remote
    attacker with the ability to spoof or control an RMI
    server connection can exploit this to execute arbitrary
    code. (CVE-2017-5983)

  - An unspecified flaw exists in the XML Parser and Action
    Message Format (AMF3) deserializer components that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-5983)

  - An XML external entity (XXE) vulnerability exists in the
    XML Parser and Action Message Format (AMF3) deserializer
    components due to improper validation of XML documents
    embedded in AMF3 messages. An unauthenticated, remote 
    attacker can exploit this to disclose sensitive
    information. (CVE-2017-5983)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://confluence.atlassian.com/jira/jira-security-advisory-2017-03-09-879243455.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53ca783d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 6.3.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5983");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');


app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

constraints = [
  { 'min_version' : '4.2.4', 'fixed_version' : '6.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
