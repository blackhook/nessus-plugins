#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117405);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-11235", "CVE-2018-13385", "CVE-2018-13386");
  script_bugtraq_id(102926);

  script_name(english:"Atlassian SourceTree 1.0b2 < 2.7.6 Remote Code Execution Vulnerabilities (Mac OSX)");
  script_summary(english:"Checks the version of Atlassian SourceTree.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian SourceTree installed on the remote host is 
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian SourceTree installed on the remote host
is a version 1.0b2 prior to 2.7.6 on Mac OSX. It is, therefore, 
affected by multiple vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://confluence.atlassian.com/sourcetreekb/sourcetree-security-advisory-2018-07-18-953674465.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c961adc1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian SourceTree 2.7.6 on Mac OSX or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13385");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:sourcetree");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("atlassian_sourcetree_detect_macosx.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/SourceTree");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

get_kb_item_or_exit("Host/MacOSX/Version");
get_kb_item_or_exit("Host/local_checks_enabled");

#atlassian_sourcetree add conversions for b --> beta and a --> alpha
vcf::atlassian_sourcetree::initialize();

app_info = vcf::get_app_info(app:"SourceTree");

constraints = [{ "min_version" : "1.0b2", "fixed_version" :  "2.7.6"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
