#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(122854);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/23");

  script_cve_id(
    "CVE-2018-17456",
    "CVE-2018-20234",
    "CVE-2018-20235",
    "CVE-2018-20236"
  );
  script_bugtraq_id(105523);

  script_name(english:"Atlassian SourceTree 0.5a < 3.0.17 Multiple remote code execution vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian SourceTree installed on the remote Windows
host is affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian SourceTree installed on the remote Windows
host is version 0.5a prior to 3.0.17. It is, therefore, affected by
multiple remote code execution vulnerabilities.

  - An option injection vulnerability exists in the git submodule
  component. An unauthenticated, remote attacker can exploit this via
  the processing of a recursive git clone of a project with a
  specially crafted .gitmodules file, to execute arbitrary commands.
  (CVE-2018-17456)

  - An argument injection vulnerability exists in the Mercurial
  repository component. An authenticated, remote attacker can exploit
  this via filenames in the Mercurial repositories to execute
  arbitrary commands. (CVE-2018-20234, CVE-2018-20235)

  - A command injection vulnerability exists in the URI handling
  component. An unauthenticated, remote attacker could exploit this
  via sending a malicious URI to a victim to execution arbitrary
  commands. (CVE-2018-20236)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://confluence.atlassian.com/sourcetreekb/sourcetree-security-advisory-2019-03-06-966678691.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9103cc4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian SourceTree 3.0.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20236");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-17456");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Malicious Git HTTP Server For CVE-2018-17456');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:sourcetree");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("atlassian_sourcetree_detect.nbin");
  script_require_keys("installed_sw/SourceTree");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

app_info = vcf::get_app_info(app:"SourceTree");

#atlassian_sourcetree add conversions for b --> beta and a --> alpha  
vcf::atlassian_sourcetree::initialize(); 

constraints = [{ "min_version" : "0.5a", "fixed_version" : "3.0.17" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
