#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101900);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-5019",
    "CVE-2017-10038",
    "CVE-2017-10046",
    "CVE-2017-10131",
    "CVE-2017-10160"
  );
  script_bugtraq_id(
    93236,
    99751,
    99757,
    99770,
    99793
  );

  script_name(english:"Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM) Multiple Vulnerabilities (July 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera
P6 Enterprise Project Portfolio Management (EPPM) installation running
on the remote web server is 8.3.x prior to 8.3.15.4, 8.4.x prior to
8.4.15.2, 15.x prior to 15.2.15.1, or 16.x prior to 16.2.9.0. It is,
therefore, affected by the following vulnerabilities :

  - A flaw exists in the Web Access component, specifically
    in Apache MyFaces Trinidad in CoreResponseStateManager,
    due to using ObjectInputStream and ObjectOutputStream
    strings directly without securely deserializing Java
    input. An unauthenticated, remote attacker can exploit
    this, via a crafted serialized view state string, to
    execute arbitrary code. (CVE-2016-5019)

  - Multiple unspecified flaws exist in the Web Access
    component that allow an authenticated, remote attacker
    to disclose sensitive information. (CVE-2017-10038,
    CVE-2017-10160)

  - An unspecified flaw exists in the Web Access component
    that allows an authenticated, remote attacker to
    impact confidentiality and integrity. (CVE-2017-10046)

  - An unspecified flaw exists in the Web Access component
    that allows an authenticated, remote attacker to
    impact confidentiality, integrity, and availability.
    (CVE-2017-10131)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76f5def7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Primavera P6 Enterprise Project Portfolio Management
(EPPM) version 8.3.15.4 / 8.4.15.2 / 15.2.15.1 / 16.2.9.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5019");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_p6_enterprise_project_portfolio_management");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_p6_eppm.nbin");
  script_require_keys("installed_sw/Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)", "www/weblogic");
  script_require_ports("Services/www", 8004);

  exit(0);
}

include("http.inc");
include("vcf.inc");

get_install_count(app_name:"Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)", exit_if_zero:TRUE);

port = get_http_port(default:8004);
get_kb_item_or_exit("www/weblogic/" + port + "/installed");

app_info = vcf::get_app_info(app:"Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)", port:port);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "8.3.0.0", "max_version" : "8.3.15.4", "fixed_version" : "8.3.15.4" },
  { "min_version" : "8.4.0.0", "max_version" : "8.4.15.2", "fixed_version" : "8.4.15.2" },
  { "min_version" : "15.0.0.0", "max_version" : "15.2.15.1", "fixed_version" : "15.2.15.1" },
  { "min_version" : "16.0.0.0", "max_version" : "16.2.9.0", "fixed_version" : "16.2.9.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE); 

