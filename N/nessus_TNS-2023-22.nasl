#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177925);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/04");

  script_cve_id(
    "CVE-2023-0465",
    "CVE-2023-0466",
    "CVE-2023-1255",
    "CVE-2023-2650"
  );

  script_name(english:"Tenable Nessus < 10.5.3 Multiple Vulnerabilities (TNS-2023-22)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Nessus installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus application running on the remote host is prior to 10.5.3. It
is, therefore, affected by multiple vulnerabilities as referenced in the TNS-2023-22 advisory.

  - Nessus leverages third-party software to help provide underlying functionality. One of the third-party
    components (OpenSSL) was found to contain vulnerabilities, and updated versions have been made available
    by the provider. Out of caution and in line with best practice, Tenable has opted to upgrade these
    components to address the potential impact of the issues. Nessus 10.5.3 updates OpenSSL to version 3.0.9
    to address the identified vulnerabilities. Tenable has released Nessus 10.5.3 to address these issues.
    The installation files can be obtained from the Tenable Downloads Portal
    (https://www.tenable.com/downloads/nessus). (CVE-2023-0465, CVE-2023-0466, CVE-2023-1255, CVE-2023-2650)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.tenable.com/release-notes/Content/nessus/nessus2023.htm#10.5.3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48b7ba11");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2023-22");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus 10.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0466");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nessus_detect.nasl", "nessus_installed_win.nbin", "nessus_installed_linux.nbin", "macos_nessus_installed.nbin");
  script_require_keys("installed_sw/Tenable Nessus");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Tenable Nessus');

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'max_version' : '10.5.2', 'fixed_version' : '10.5.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
