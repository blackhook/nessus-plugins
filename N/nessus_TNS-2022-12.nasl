##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161617);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2022-23852",
    "CVE-2022-23990",
    "CVE-2022-25235",
    "CVE-2022-25236",
    "CVE-2022-25313",
    "CVE-2022-25314",
    "CVE-2022-25315"
  );

  script_name(english:"Tenable Nessus 8.x < 8.15.5 Third-Party Vulnerabilities (TNS-2022-12)");

  script_set_attribute(attribute:"synopsis", value:
"Tenable Nessus running on the remote host is affected by multiple third-party vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus application running on the remote host is 8.x prior to 
8.15.5. It is, therefore, affected by multiple vulnerabilities in third-party libraries, including:

  - An integer overflow in storeRawNames in Expat (aka libexpat) before 2.4.5. (CVE-2022-25315)

  - Expat (aka libexpat) before 2.4.4 has an integer overflow in the doProlog function. (CVE-2022-23990)

  - Expat (aka libexpat) before 2.4.4 has a signed integer overflow in XML_GetBuffer, for configurations with a nonzero XML_CONTEXT_BYTES. (CVE-2022-23852)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2022-12");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus version 8.15.5 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25315");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/27");

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
  {'min_version':'8.0.0', 'fixed_version':'8.15.5'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);