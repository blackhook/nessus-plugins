#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150798);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2018-20843",
    "CVE-2019-15903",
    "CVE-2019-16168",
    "CVE-2021-20099",
    "CVE-2021-20100"
  );
  script_xref(name:"IAVB", value:"2021-B-0039");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Tenable Nessus 8.x.x < 8.15.0 Multiple Vulnerabilities (TNS-2021-11)");

  script_set_attribute(attribute:"synopsis", value:
"Tenable Nessus running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus application running on the remote host is prior to 
8.15.0. It is, therefore, affected by multiple vulnerabilities:

  - Multiple local privilege escalation vulnerabilities. A local attacker can exploit these to gain administrator
    privileges to the system. (CVE-2021-20099, CVE-2021-20100)

  - In libexpat in Expat before 2.2.7, XML input including XML names that contain a large number of colons could make
    the XML parser consume a high amount of RAM and CPU resources while processing (enough to be usable for
    denial-of-service attacks). (CVE-2018-20843)

  - In libexpat before 2.2.8, crafted XML input could fool the parser into changing from DTD parsing to document
    parsing too early; a consecutive call to XML_GetCurrentLineNumber (or XML_GetCurrentColumnNumber) then resulted in
    a heap-based buffer over-read. (CVE-2019-15903)

  - In SQLite through 3.29.0, whereLoopAddBtreeIndex in sqlite3.c can crash a browser or other application because of
    missing validation of a sqlite_stat1 sz field, aka a 'severe division by zero in the query planner.'
    (CVE-2019-16168)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2021-11");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus version 8.15.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20100");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '8.0.0', 'fixed_version' : '8.15.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

