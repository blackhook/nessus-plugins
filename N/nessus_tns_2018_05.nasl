#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110096);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2018-1147", "CVE-2018-1148");

  script_name(english:"Tenable Nessus < 7.1.0 Multiple Vulnerabilities (TNS-2018-05)");

  script_set_attribute(attribute:"synopsis", value:
"Tenable Nessus running on the remote host is affected by 
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus application
running on the remote host is prior to 7.1.0. It is, therefore,
affected by multiple vulnerabilities:

  - Tenable Nessus contains a flaw that allows a stored cross-site 
    scripting (XSS) attack. This flaw exists because the program 
    does not properly sanitize input to a specially crafted .nessus 
    file before returning it to users. This may allow an authenticated 
    remote attacker to create a specially crafted request that 
    executes arbitrary script code in a user's browser session 
    within the trust relationship between their browser and the 
    server. (CVE-2018-1147)

  - Tenable Nessus contains a flaw that allows conducting a session 
    fixation attack. This flaw exists because the application, when 
    establishing a new session, does not invalidate an existing 
    session identifier and assign a new one. With a specially 
    crafted request fixating the session identifier, a 
    context-dependent attacker can ensure a user authenticates with 
    the known session identifier, allowing the session to be 
    subsequently hijacked. (CVE-2018-1148)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2018-05");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus version 7.1.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1148");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
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
  { "fixed_version" : "7.1.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
