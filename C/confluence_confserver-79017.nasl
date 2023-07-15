##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161848);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/05");

  script_cve_id("CVE-2016-10750");

  script_name(english:"Atlassian Confluence 7.4.x < 7.4.17 / 7.13.x < 7.13.7 / 7.14.x < 7.14.3 / 7.15.x < 7.15.2 / 7.16.x < 7.16.4 / 7.17.x < 7.17.4 / 7.18.x < 7.18.1 (CONFSERVER-79017)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence installed on the remote host is prior to 7.4.x < 7.4.17 / 7.13.x < 7.13.7 / 7.14.x <
7.14.3 / 7.15.x < 7.15.2 / 7.16.x < 7.16.4 / 7.17.x < 7.17.4 / 7.18.x < 7.18.1. It is, therefore, affected by a
vulnerability as referenced in the CONFSERVER-79017 advisory.

  - *Summary* A remote attacker who can connect to the Hazelcast service, running on port 5801 (and
    potentially 5701), is able to execute arbitrary code on all the nodes in a Confluence Data Center through
    Java deserialization. *Vulnerability Details* Confluence Data Center uses the third-party software
    Hazelcast, which is vulnerable to Java deserialization attacks (CVE-2016-10750). Hazelcast provides
    functionality needed to run Confluence Data Center as a cluster. A remote, unauthenticated attacker can
    exploit this vulnerability by sending a specially crafted JoinRequest, resulting in arbitrary code
    execution. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0
    before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from
    7.18.0 before 7.18.1. (atlassian-CONFSERVER-79017)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-79017");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, 7.17.4, 7.18.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10750");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl");
  script_require_keys("installed_sw/confluence");
  script_require_ports("Services/www", 8080, 8090);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80);
var app_info = vcf::get_app_info(app:'confluence', port:port, webapp:true);

var constraints = [
  { 'min_version' : '7.4.0', 'fixed_version' : '7.4.17' },
  { 'min_version' : '7.13.0', 'fixed_version' : '7.13.7' },
  { 'min_version' : '7.14.0', 'fixed_version' : '7.14.3' },
  { 'min_version' : '7.15.0', 'fixed_version' : '7.15.2' },
  { 'min_version' : '7.16.0', 'fixed_version' : '7.16.4' },
  { 'min_version' : '7.17.0', 'fixed_version' : '7.17.4' },
  { 'min_version' : '7.18.0', 'fixed_version' : '7.18.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
