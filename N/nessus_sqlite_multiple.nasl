#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88964);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2015-5895");

  script_name(english:"Nessus SQLite Multiple RCE");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple
remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Nessus
running on the remote host is affected by multiple remote code
execution vulnerabilities in the bundled version of SQLite due to
heap-based buffer overflow conditions in the sqlite3VdbeExec() and
resolve_backslashes() functions. A remote attacker can exploit these
issues to cause a denial of service condition or the execution of
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2015-05");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nessus version 5.2.11 / 6.3.7 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5895");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sqlite:sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nessus_detect.nasl", "nessus_installed_win.nbin", "nessus_installed_linux.nbin", "macos_nessus_installed.nbin");      				  
  script_require_keys("installed_sw/Tenable Nessus");

  exit(0);
}

include('vcf_extras.inc');

var app_info, constraints;

app_info = vcf::combined_get_app_info(app:'Tenable Nessus');

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "5.2.0",  "fixed_version" : "5.2.11" },
  { "min_version" : "6.0.0",  "fixed_version" : "6.3.7" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
