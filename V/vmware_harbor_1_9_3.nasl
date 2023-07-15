#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132856);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/24");

  script_cve_id(
    "CVE-2019-3990",
    "CVE-2019-19023",
    "CVE-2019-19025",
    "CVE-2019-19026",
    "CVE-2019-19029"
  );

  script_name(english:"VMware Harbor 1.7.x, 1.8.x < 1.8.6 / 1.9.x < 1.9.3");

  script_set_attribute(attribute:"synopsis", value:
"A cloud native registry installed on the remote host is affected multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Harbor installed on the remote host is 1.7.x or 1.8.x prior to 1.8.6 or 1.9.x prior to 1.9.3. It
is, therefore, affected multiple vulnerabilities, including the following:

  - A privilege escalation vulnerability that allows an authenticated, normal user to gain administrative
    account privileges by making an API call to modify the email address of a specific user. An attacker can
    reset the password for that email address to gain access to the administrative account. This vulnerability
    exists because the affected Harbor API fails to enforce proper permissions and scope on the API request to
    modify an email address. (CVE-2019-19023)

  - A Cross-Site Request Forgery (CSRF) vulnerability caused by the Harbor web interface failing to implement
    protection mechanisms against CSRF. An unauthenticated, remote attacker can exploit this, by luring an
    authenticated user onto a prepared third-party website, in order to execute any action the platform in the
    context of the currently authenticated victim. (CVE-2019-19025)

  - An SQL injection (SQLi) vulnerability which a remote, authenticated user with Project-Admin capabilities
    can exploit by sending a specially crafted SQL payload in order to read secrets from the underlying
    database or conduct privilege escalation. (CVE-2019-19029)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/goharbor/harbor/security/advisories/GHSA-qcfv-8v29-469w
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9e14e46");
  # https://github.com/goharbor/harbor/security/advisories/GHSA-rh89-vvrg-fg64
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9d62b62");
  # https://github.com/goharbor/harbor/security/advisories/GHSA-gcqm-v682-ccw6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9815c178");
  # https://github.com/goharbor/harbor/security/advisories/GHSA-6qj9-33j4-rvhg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a9ee701");
  # https://github.com/goharbor/harbor/security/advisories/GHSA-3868-7c5x-4827
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c3e5deb");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Harbor version 1.8.6, 1.9.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19025");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:goharbor:harbor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cncf_harbor_web_detect.nbin", "cncf_harbor_local_detect.nbin");
  script_require_keys("installed_sw/Harbor");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');

app = 'Harbor';
get_kb_item_or_exit('installed_sw/' + app);

app_info = vcf::combined_get_app_info(app:app);

constraints = [
  { 'min_version' : '1.7', 'fixed_version' : '1.8.6' },
  { 'min_version' : '1.9', 'fixed_version' : '1.9.3' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{sqli:TRUE, xsrf:TRUE}
);

