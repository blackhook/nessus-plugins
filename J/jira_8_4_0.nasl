#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129099);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2019-8449",
    "CVE-2019-8451",
    "CVE-2019-14995",
    "CVE-2019-14997",
    "CVE-2019-14998"
  );

  script_name(english:"Atlassian JIRA < 8.4.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian JIRA hosted on the remote web server is prior
to prior to 8.4.0. It is, therefore, affected by multiple vulnerabilities:

    - An authorization bypass vulnerability exists in the 
      /rest/issueNav/1/issueTable resource as well as the 
      /rest/api/latest/groupuserpicker resource. An unauthenticated, 
      remote attacker can exploit this, to enumerate usernames due to 
      an incorrect authorization check. (CVE-2019-8449)
    
    - A server-side request forgery (SSRF) vulnerability exists in 
      the /plugins/servlet/gadgets/makeRequest resource due to a 
      logic bug in the JiraWhitelist class.  A remote attacker can 
      exploit this to access the content of internal network 
      resources via a Server Side Request Forgery (SSRF) 
      vulnerability. (CVE-2019-8451)
   
    - An authentication bypass vulnerability exists in the 
      /rest/api/1.0/render rest resource. An unauthenticated, 
      remote attacker can exploit this, to determine if an attachment
      with a specific name exists and if an issue key is valid due 
      to a missing permissions check. (CVE-2019-14995)

    - An information disclosure vulnerability exists in the 
      AccessLogFilter class due to a caching vulnerability. A remote 
      anonymous attackers can exploit this to access details about 
      other users, including their username, when Jira is configured 
      with a reverse Proxy and or a load balancer with caching or a 
      CDN. (CVE-2019-14997)

    - A cross-site request forgery (XSRF) vulnerability exists 
      in Webwork action Cross-Site Request Forgery (CSRF) protection. 
      A remote attacker can exploit this by bypassing its protection
      by 'cookie tossing' a CSRF cookie from a subdomain of a Jira 
      instance. (CVE-2019-14998)");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69791");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69792");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69793");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69794");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69796");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 8.4.0");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8451");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Atlassian JIRA Username Enumeration");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');


app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

constraints = [
  { 'min_version' : '7.0.0', 'fixed_version' : '8.4.0' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags: {'xsrf':TRUE});
