##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161440);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/23");

  script_cve_id(
    "CVE-2022-29036",
    "CVE-2022-29037",
    "CVE-2022-29038",
    "CVE-2022-29039",
    "CVE-2022-29040",
    "CVE-2022-29041",
    "CVE-2022-29042",
    "CVE-2022-29043",
    "CVE-2022-29044",
    "CVE-2022-29045",
    "CVE-2022-29046",
    "CVE-2022-29047",
    "CVE-2022-29048",
    "CVE-2022-29049",
    "CVE-2022-29050",
    "CVE-2022-29051",
    "CVE-2022-29052"
  );

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2022-04-12)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its their self-reported version number, the version of Jenkins plugins running on the remote web server are
Jenkins CVS Plugin prior to 2.19.1, Credentials Plugin prior to 1112., Extended Choice Parameter Plugin 346. or earlier,
Gerrit Trigger Plugin prior to 2.35.3, Git Parameter Plugin prior to 0.9.16, Google Compute Engine Plugin prior to
4.3.9, Jira Plugin prior to 3.7.1, Job Generator Plugin 1.22 or earlier, Mask Passwords Plugin prior to 3.1, Node and
Label parameter Plugin prior to 1.10.3.1, Pipeline: Shared Groovy Libraries Plugin prior to 566., Publish Over FTP
Plugin prior to 1.17, Subversion Plugin prior to 2.15.4, promoted builds Plugin prior to 876.. They are, therefore,
affected by multiple vulnerabilities:

  - Jenkins Credentials Plugin 1111.v35a_307992395 and earlier, except 1087.1089.v2f1b_9a_b_040e4,
    1074.1076.v39c30cecb_0e2, and 2.6.1.1, does not escape the name and description of Credentials parameters
    on views displaying parameters, resulting in a stored cross-site scripting (XSS) vulnerability exploitable
    by attackers with Item/Configure permission. (CVE-2022-29036)

  - Jenkins Extended Choice Parameter Plugin 346.vd87693c5a_86c and earlier does not escape the name and
    description of Extended Choice parameters on views displaying parameters, resulting in a stored cross-site
    scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-29038)

  - Jenkins Gerrit Trigger Plugin 2.35.2 and earlier does not escape the name and description of Base64
    Encoded String parameters on views displaying parameters, resulting in a stored cross-site scripting (XSS)
    vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-29039)

  - Jenkins Git Parameter Plugin 0.9.15 and earlier does not escape the name and description of Git parameters
    on views displaying parameters, resulting in a stored cross-site scripting (XSS) vulnerability exploitable
    by attackers with Item/Configure permission. (CVE-2022-29040)

  - Jenkins Jira Plugin 3.7 and earlier, except 3.6.1, does not escape the name and description of Jira Issue
    and Jira Release Version parameters on views displaying parameters, resulting in a stored cross-site
    scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-29041)

  - Jenkins Job Generator Plugin 1.22 and earlier does not escape the name and description of Generator
    Parameter and Generator Choice parameters on Job Generator jobs' Build With Parameters views, resulting in
    a stored cross-site scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission.
    (CVE-2022-29042)

  - Jenkins Mask Passwords Plugin 3.0 and earlier does not escape the name and description of Non-Stored
    Password parameters on views displaying parameters, resulting in a stored cross-site scripting (XSS)
    vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-29043)

  - Jenkins Node and Label parameter Plugin 1.10.3 and earlier does not escape the name and description of
    Node and Label parameters on views displaying parameters, resulting in a stored cross-site scripting (XSS)
    vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-29044)

  - Jenkins promoted builds Plugin 873.v6149db_d64130 and earlier, except 3.10.1, does not escape the name and
    description of Promoted Build parameters on views displaying parameters, resulting in a stored cross-site
    scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-29045)

  - Jenkins Subversion Plugin 2.15.3 and earlier does not escape the name and description of List Subversion
    tags (and more) parameters on views displaying parameters, resulting in a stored cross-site scripting
    (XSS) vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-29046)

  - Jenkins Pipeline: Shared Groovy Libraries Plugin 564.ve62a_4eb_b_e039 and earlier, except 2.21.3, allows
    attackers able to submit pull requests (or equivalent), but not able to commit directly to the configured
    SCM, to effectively change the Pipeline behavior by changing the definition of a dynamically retrieved
    library in their pull request, even if the Pipeline is configured to not trust them. (CVE-2022-29047)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Subversion Plugin 2.15.3 and earlier allows
    attackers to connect to an attacker-specified URL. (CVE-2022-29048)

  - Jenkins promoted builds Plugin 873.v6149db_d64130 and earlier, except 3.10.1, does not validate the names
    of promotions defined in Job DSL, allowing attackers with Job/Configure permission to create a promotion
    with an unsafe name. (CVE-2022-29049)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Publish Over FTP Plugin 1.16 and earlier
    allows attackers to connect to an FTP server using attacker-specified credentials. (CVE-2022-29050)

  - Missing permission checks in Jenkins Publish Over FTP Plugin 1.16 and earlier allow attackers with
    Overall/Read permission to connect to an FTP server using attacker-specified credentials. (CVE-2022-29051)

  - Jenkins Google Compute Engine Plugin 4.3.8 and earlier stores private keys unencrypted in cloud agent
    config.xml files on the Jenkins controller where they can be viewed by users with Extended Read
    permission, or access to the Jenkins controller file system. (CVE-2022-29052)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2022-04-12");
  script_set_attribute(attribute:"solution", value:
"Upgrade promoted builds Plugin to version 876. or later, Subversion Plugin to version 2.15.4 or later, Publish Over FTP
Plugin to version 1.17 or later, Pipeline: Shared Groovy Libraries Plugin to version 566. or later, Node and Label
parameter Plugin to version 1.10.3.1 or later, Mask Passwords Plugin to version 3.1 or later, Jira Plugin to version
3.7.1 or later, Google Compute Engine Plugin to version 4.3.9 or later, Git Parameter Plugin to version 0.9.16 or later,
Gerrit Trigger Plugin to version 2.35.3 or later, Credentials Plugin to version 1112. or later, CVS Plugin to version
2.19.1 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29048");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('jenkins_plugin_mappings.inc');

var constraints = [
    {'fixed_version' : '3.10.1', 'fixed_display' : '3.10.1 / 876.v99d29788b_36b_', 'plugin' : jenkins_plugin_mappings['promoted builds Plugin']},
    {'min_version' : '800', 'max_version' : '873.', 'fixed_version' : '876.', 'fixed_display' : '3.10.1 / 876.v99d29788b_36b_', 'plugin' : jenkins_plugin_mappings['promoted builds Plugin']},
    {'max_version' : '2.15.3', 'fixed_version' : '2.15.4', 'plugin' : jenkins_plugin_mappings['Subversion Plugin']},
    {'max_version' : '1.16', 'fixed_version' : '1.17', 'plugin' : jenkins_plugin_mappings['Publish Over FTP Plugin']},
    {'fixed_version' : '2.21.3', 'fixed_display' : '2.21.3 / 566.vd0a_a_3334a_555', 'plugin' : jenkins_plugin_mappings['Pipeline: Shared Groovy Libraries Plugin']},
    {'min_version' : '500', 'max_version' : '564.', 'fixed_version' : '566.', 'fixed_display' : '2.21.3 / 566.vd0a_a_3334a_555', 'plugin' : jenkins_plugin_mappings['Pipeline: Shared Groovy Libraries Plugin']},
    {'max_version' : '1.10.3', 'fixed_version' : '1.10.3.1', 'plugin' : jenkins_plugin_mappings['Node and Label parameter Plugin']},
    {'max_version' : '3.0', 'fixed_version' : '3.1', 'plugin' : jenkins_plugin_mappings['Mask Passwords Plugin']},
    {'max_version' : '1.22', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Job Generator Plugin']},
    {'fixed_version' : '3.6.1', 'fixed_display' : '3.6.1 / 3.7.1', 'plugin' : jenkins_plugin_mappings['Jira Plugin']},
    {'min_version' : '3.7', 'fixed_version' : '3.7.1', 'plugin' : jenkins_plugin_mappings['Jira Plugin']},
    {'max_version' : '4.3.8', 'fixed_version' : '4.3.9', 'plugin' : jenkins_plugin_mappings['Google Compute Engine Plugin']},
    {'max_version' : '0.9.15', 'fixed_version' : '0.9.16', 'plugin' : jenkins_plugin_mappings['Git Parameter Plugin']},
    {'max_version' : '2.35.2', 'fixed_version' : '2.35.3', 'plugin' : jenkins_plugin_mappings['Gerrit Trigger Plugin']},
    {'max_version' : '346.', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Extended Choice Parameter Plugin']},
    {'fixed_version' : '2.6.1.1', 'fixed_display' : '2.6.1.1 / 1074.1076.v39c30cecb_0e2 / 1087.1089.v2f1b_9a_b_040e4 / 1112.vc87b_7a_3597f6', 'plugin' : jenkins_plugin_mappings['Credentials Plugin']},
    {'min_version' : '1000', 'fixed_version' : '1074.1076.', 'fixed_display' : '2.6.1.1 / 1074.1076.v39c30cecb_0e2 / 1087.1089.v2f1b_9a_b_040e4 / 1112.vc87b_7a_3597f6', 'plugin' : jenkins_plugin_mappings['Credentials Plugin']},
    {'min_version' : '1075', 'fixed_version' : '1087.1089.', 'fixed_display' : '2.6.1.1 / 1074.1076.v39c30cecb_0e2 / 1087.1089.v2f1b_9a_b_040e4 / 1112.vc87b_7a_3597f6', 'plugin' : jenkins_plugin_mappings['Credentials Plugin']},
    {'min_version' : '1088', 'fixed_version' : '1112.', 'fixed_display' : '2.6.1.1 / 1074.1076.v39c30cecb_0e2 / 1087.1089.v2f1b_9a_b_040e4 / 1112.vc87b_7a_3597f6', 'plugin' : jenkins_plugin_mappings['Credentials Plugin']},
    {'max_version' : '2.19', 'fixed_version' : '2.19.1', 'plugin' : jenkins_plugin_mappings['CVS Plugin']}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

var flags = {'xsrf':TRUE, 'xss':TRUE};
vcf::jenkins::plugin::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:flags);
