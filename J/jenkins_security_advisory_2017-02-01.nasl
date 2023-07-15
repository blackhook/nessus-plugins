#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97609);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2011-4969",
    "CVE-2015-0886",
    "CVE-2016-9887",
    "CVE-2017-2598",
    "CVE-2017-2599",
    "CVE-2017-2600",
    "CVE-2017-2601",
    "CVE-2017-2602",
    "CVE-2017-2603",
    "CVE-2017-2604",
    "CVE-2017-2606",
    "CVE-2017-2607",
    "CVE-2017-2608",
    "CVE-2017-2609",
    "CVE-2017-2610",
    "CVE-2017-2611",
    "CVE-2017-2612",
    "CVE-2017-2613",
    "CVE-2017-1000362"
  );
  script_bugtraq_id(
    58458,
    95948,
    95949,
    95951,
    95952,
    95953,
    95954,
    95955,
    95956,
    95957,
    95959,
    95960,
    95961,
    95962,
    95963,
    95964,
    95967
  );

  script_name(english:"Jenkins < 2.44 / 2.32.x < 2.32.2, Jenkins Operations Center < 1.625.22.1 / 2.7.22.0.1 / 2.32.2.1, and Jenkins Enterprise < 1.651.22.1 / 2.7.22.0.1 / 2.32.2.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a job scheduling and management system
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of Jenkins that is prior to
2.44, or a version of Jenkins LTS prior to 2.32.2, or else a version
of Jenkins Operations Center that is 1.625.x.y prior to 1.625.22.1,
2.7.x.0.y prior to 2.7.22.0.1, or 2.x.y.x prior to 2.32.2.1, or else a
version of Jenkins Enterprise that is 1.651.x.y prior to 1.651.22.1,
2.7.x.0.y prior to 2.7.22.0.1, or 2.x.y.z prior to 2.32.2.1. It is,
therefore, affected by the following vulnerabilities :

  - A DOM-based cross-site scripting (XSS) vulnerability
    exists in jQuery Core due to improper validation of
    certain tags while being rendered using innerHTML. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted request, to execute arbitrary script
    code in the user's browser session. (CVE-2011-4969)

  - An integer overflow condition exists in jBCrypt in the
    key stretching implementation in gensalt, within the
    crypt_raw() function, which is triggered when the
    'log_rounds' parameter is set to the maximum value (31).
    An unauthenticated, remote attacker can exploit this to
    cause log_rounds to perform zero rounds, allowing a
    brute-force attack to more easily determine the password
    hash. (CVE-2015-0886)

  - A cross-site request forgery vulnerability (XSRF) exists
    due to several URLs related to group and role management
    not requiring POST form submission. An unauthenticated,
    remote attacker can exploit this to create unused roles,
    delete unused roles, and set group descriptions. Note
    that only Jenkins Enterprise is affected by this issue.
    (CVE-2016-9887)

  - A flaw exists when sensitive data, such as passwords, is
    encrypted using AES-128 with electronic codebook mode
    (ECB). An authenticated, remote attacker can exploit
    this to disclose information about reused passwords.
    (CVE-2017-2598)

  - An unspecified flaw exists that is triggered when
    handling new items due to insufficient permission
    checks. An authenticated, remote attacker can exploit
    this, by using the name of an already existing item, to
    create a new item that overwrites the existing item or
    to gain access to related objects. (CVE-2017-2599)

  - An information disclosure vulnerability exists due to
    improper permissions being set for accessing node
    monitor data via the remote API. An authenticated,
    remote attacker can exploit this to disclose system
    configuration and runtime information. (CVE-2017-2600)

  - A stored cross-site scripting (XSS) vulnerability exists
    due to improper validation of input to names and
    descriptions fields before returning it to users. An
    authenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2017-2601)

  - A flaw exists in the Agent-to-Master Security Subsystem
    because build metadata from the Pipeline suite is not
    properly blacklisted. An authenticated, remote attacker
    can exploit this to overwrite metadata files.
    (CVE-2017-2602)

  - A flaw exists in the config.xml API when handling
    user-initiated agent disconnects, which results in User
    objects being included in the agent API output. An
    authenticated, remote attacker can exploit this to
    disclose sensitive information (e.g., user API tokens).
    (CVE-2017-2603)

  - A flaw exists when handling permissions for
    administrative monitors that allows an authenticated,
    remote attacker to access certain provided actions.
    (CVE-2017-2604)

  - A flaw exists in the internal API, specifically within
    the Jenkins::getItems() function, when requesting a list
    of items via UnprotectedRootAction. An authenticated,
    remote attacker can exploit this to disclose information
    regarding otherwise restricted items. (CVE-2017-2606)

  - A stored cross-site scripting (XSS) vulnerability exists
    due to improper validation of input passed via
    serialized console notes before returning it to users in
    build logs. An authenticated, remote attacker can
    exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (CVE-2017-2607)

  - A flaw exists in the XStream-based API due to improper
    validation of user-supplied input before it is
    deserialized. An authenticated, remote attacker can
    exploit this, via a specially crafted request, to
    execute arbitrary code. (CVE-2017-2608)

  - A flaw exists in the search box implementation due to
    the autocompletion feature displaying the names of
    restricted views. An authenticated, remote attacker can
    exploit this to disclose sensitive names of views.
    (CVE-2017-2609)

  - A stored cross-site scripting (XSS) vulnerability exists
    due to improper validation of input passed in user names
    before returning it to users. An authenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2017-2610)

  - A flaw exists due to improper validation of permissions
    to the /workspaceCleanup and /fingerprintCleanup URLs.
    An authenticated, remote attacker can exploit this to
    cause a high load on the master and agents.
    (CVE-2017-2611)

  - A flaw exists due to a failure to properly restrict
    access to JDK download credentials. An authenticated,
    remote attacker can exploit this to overwrite the
    credentials, thereby causing builds to fail.
    (CVE-2017-2612)

  - A cross-site request forgery (XSRF) vulnerability exists
    due to a failure by HTTP GET requests to /user to
    require multiple steps, explicit confirmation, or a
    unique token when performing certain sensitive actions.
    An unauthenticated, remote attacker can exploit this, by
    convincing a user to follow a specially crafted link, to
    cause the creation of new temporary users.
    (CVE-2017-2613)

  - An information disclosure vulnerability which exists in 
    its re-key admin monitor component due to world readable 
    permissions being set on the directory it creates to 
    store secret information. An unauthenticated, remote 
    attacker can exploit this to disclose information 
    contained in this directory.
    (CVE-2017-1000362)");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2017-02-01/");
  script_set_attribute(attribute:"see_also", value:"https://www.cloudbees.com/cloudbees-security-advisory-2017-02-01");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/changelog/");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/changelog-stable/");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.44 or later, Jenkins LTS to version
2.32.2 or later, or Jenkins Operations Center to version 1.625.22.1 /
2.7.22.0.1 / 2.32.2.1 or later, or Jenkins Enterprise to version
1.651.22.1 / 2.7.22.0.1 / 2.32.2.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-2608");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'fixed_version' : '2.44',    'edition':'Open Source' },
  { 'fixed_version' : '2.32.2',  'edition':'Open Source LTS' },
  { 'min_version' : '1',    'fixed_version' : '1.651.22.1', 'edition':'Enterprise' },
  { 'min_version' : '1',    'fixed_version' : '1.625.22.1', 'edition':'Operations Center' },
  { 'min_version' : '2.7',  'fixed_version' : '2.7.22.0.1', 'edition':make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2',    'fixed_version' : '2.32.2.1',   'edition':make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE}
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE, xsrf:TRUE}
);
