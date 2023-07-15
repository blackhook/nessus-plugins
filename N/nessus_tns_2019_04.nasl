#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(126627);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2019-3961", "CVE-2019-3962");
  script_bugtraq_id(108892);

  script_name(english:"Tenable Nessus < 8.5.0 Multiple Vulnerabilities (TNS-2019-04)");

  script_set_attribute(attribute:"synopsis", value:
"Tenable Nessus running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus application running on the remote host is prior to 8.5.0.
It is, therefore, affected by multiple vulnerabilities:

  - A reflected XSS vulnerability due to improper validation of user-supplied input. An unauthenticated, remote
    attacker could potentially exploit this vulnerability via a specially crafted request to execute arbitrary script
    code in a users browser session. (CVE-2019-3961)

  - A content injection vulnerability. An authenticated, local attacker could exploit this vulnerability by convincing
    another targeted Nessus user to view a malicious URL and use Nessus to send fraudulent messages. Successful
    exploitation could allow the authenticated adversary to inject arbitrary text into the feed status, which will
    remain saved post session expiration. (CVE-2019-3962)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2019-04");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus version 8.5.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3962");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-3961");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/11");

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
  { "fixed_version" : "8.5.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
