#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134205);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-2912", "CVE-2018-2913", "CVE-2018-2914");
  script_bugtraq_id(105651);

  script_name(english:"Oracle GoldenGate Multiple Vulnerabilities (October 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A real-time data integration and replication application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle GoldenGate installed on the remote host is affected by the following vulnerabilities as noted in
the October 2018 CPU advisory :

  - A denial of service (DoS) vulnerability exists in the manager component of GoldenGate. An unauthenticated,
    remote attacker can exploit this by sending a malformed command via TCP, to cause the application to stop
    responding. (CVE-2018-2912, CVE-2018-2914)
  
  - A stack-based buffer overflow condition exists in the manager component of GoldenGate. An unauthenticated,
    remote attacker can exploit this by sending a malformed command via TCP, to cause a denial of service
    condition or the execution of arbitrary code. (CVE-2018-2913)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2018-31");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?705136d8");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2018 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2913");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:goldengate");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_goldengate_installed.nbin");
  script_require_keys("Oracle/GoldenGate/Installed");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_goldengate::get_app_info();

var constraints = [
  {
    'min_version'   : '12.1.2.1' ,
    'fixed_version' : '12.1.2.1.181016',
    'fixed_display' : '12.1.2.1.181016 (28696808 / 28696813)'
  },
  {
    'min_version'   : '12.2.0.2' ,
    'fixed_version' : '12.2.0.2.181009',
    'fixed_display' : '12.2.0.2.181009 (28651607 / 28651610)'
  },
  {
    'min_version'   : '12.3.0.1' ,
    'fixed_version' : '12.3.0.1.180821',
    'fixed_display' : '12.3.0.1.180821 (28498482 / 28498505)'
  },
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

