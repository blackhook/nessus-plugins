#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150139);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2019-1551",
    "CVE-2020-1967",
    "CVE-2020-1971",
    "CVE-2020-11022",
    "CVE-2020-11023",
    "CVE-2021-3449",
    "CVE-2021-23840"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Tenable Log Correlation Engine (LCE) < 6.0.9 (TNS-2021-10)");

  script_set_attribute(attribute:"synopsis", value:
"A data aggregation application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Tenable Log Correlation Engine (LCE) installed on the remote host is prior to 6.0.9. It is, therefore,
affected by multiple vulnerabilities:

  - Multiple denial of service vulnerabilities in the included OpenSSL component. (CVE-2019-1551, CVE-2020-1967,
    CVE-2020-1971, CVE-2021-3449, CVE-2021-23840)

  - Multiple cross site scripting vulnerabilities in the included JQuery component. (CVE-2020-11022, CVE-2020-11023)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2021-10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable LCE version 6.0.9 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1551");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-11023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:log_correlation_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("lce_installed.nbin");
  script_require_keys("installed_sw/Log Correlation Engine Server");

  exit(0);
}

include('vcf.inc');

var app = 'Log Correlation Engine Server';

get_install_count(app_name:app, exit_if_zero:TRUE);

var app_info = vcf::get_app_info(app:app);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'max_version' : '6.0.8', 'fixed_version' : '6.0.9' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});

