#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120197);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2018-0734", "CVE-2018-5407");

  script_name(english:"Tenable Nessus < 8.1.1 Multiple Vulnerabilities (TNS-2018-16)");

  script_set_attribute(attribute:"synopsis", value:
"Tenable Nessus running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus application
running on the remote host is 8.x prior to 8.1.1. It is, therefore,
affected by multiple vulnerabilities:

  - Tenable Nessus contains a flaw in the bundled third-party
    component OpenSSL library's DSA signature algorithm that
    renders it vulnerable to a timing side channel attack.
    An attacker could leverage this vulnerability to recover
    the private key. (CVE-2018-0734)

  - Tenable Nessus contains a flaw in the bundled third-party
    component OpenSSL library's Simultaneous Multithreading 
    (SMT) architectures which render it vulnerable to 
    side-channel leakage. This issue is known as 'PortSmash'. 
    An attacker could possibly use this issue to perform a 
    timing side-channel attack and recover private keys. 
    (CVE-2018-5407)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2018-16");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus version 8.1.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0734");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");

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
  { "min_version" : "7.2.0", "fixed_version" : "8.1.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
