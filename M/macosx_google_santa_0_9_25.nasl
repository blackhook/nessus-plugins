#
# (C) Tenable Network Security, Inc.
#

include ("compat.inc");

if (description)
{
  script_id(110519);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/05");

  script_cve_id("CVE-2018-10405");

  script_name(english:"Google Santa Code Signing Bypass (macOS)");
  script_summary(english:"Gets the Google Santa version from system_profiler.");

  script_set_attribute(attribute:"synopsis", value:
"A binary whitelisting and blacklisting application installed on
the remote macOS or Mac OS X host is vulnerable to accepting forged 
Apple signatures.");
  script_set_attribute(attribute:"description", value:
"The installed version of Google Santa is less than 0.9.25 and is 
therefore vulnerable to allowing execution of malicious binaries due 
to accepting forged Apple signatures.");
  # https://www.okta.com/security-blog/2018/06/issues-around-third-party-apple-code-signing-checks/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e9d177b");
  script_set_attribute(attribute:"see_also", value:"https://github.com/google/santa/releases/tag/0.9.25");
  script_set_attribute(attribute:"see_also", value:"https://github.com/google/santa");
  script_set_attribute(attribute:"solution", value:
"Update Google Santa to version 0.9.25 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10405");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");


  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:google:santa");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_santa_installed.nbin");
  script_require_keys("installed_sw/Santa");

  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"Santa");

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "0.0.0", "fixed_version" : "0.9.25" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
