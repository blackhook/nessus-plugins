#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124170);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2016-1000031",
    "CVE-2017-9798",
    "CVE-2018-8034",
    "CVE-2018-11763",
    "CVE-2018-11784",
    "CVE-2018-19360",
    "CVE-2018-19361",
    "CVE-2018-19362"
  );
  script_bugtraq_id(
    93604,
    100872,
    104895,
    105414,
    105524
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Primavera Unifier Multiple Vulnerabilities (Apr 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera
Unifier installation running on the remote web server is 16.x prior to
16.2.15.7 or 17.7.x prior to 17.12.10 or 18.x prior to 18.8.6. It is, 
therefore, affected by multiple vulnerabilities:

  - A deserialization vulnerability in Apache Commons
    FileUpload allows for remote code execution.
    (CVE-2016-1000031)

  - A denial of service (DoS) vulnerability exists in
    Apache HTTP Server 2.4.17 to 2.4.34, due to a design
    error. An unauthenticated, remote attacker can
    exploit this issue by sending continuous, large
    SETTINGS frames to cause a client to occupy a
    connection, server thread and CPU time without any
    connection timeout coming to effect. This affects
    only HTTP/2 connections. A possible mitigation is to
    not enable the h2 protocol. (CVE-2018-11763).

  - A deserialization vulnerability in jackson-databind, a
    fast and powerful JSON library for Java, allows an
    unauthenticated user to perform code execution. The
    issue was resolved by extending the blacklist and
    blocking more classes from polymorphic deserialization.
    (CVE-2018-19362)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9166970d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Primavera Unifier version 16.2.15.7 / 17.12.10 / 18.8.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1000031");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_unifier");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_unifier.nbin");
  script_require_keys("installed_sw/Oracle Primavera Unifier", "www/weblogic");
  script_require_ports("Services/www", 8002);

  exit(0);
}

include("http.inc");
include("vcf.inc");

get_install_count(app_name:"Oracle Primavera Unifier", exit_if_zero:TRUE);

port = get_http_port(default:8002);
get_kb_item_or_exit("www/weblogic/" + port + "/installed");

app_info = vcf::get_app_info(app:"Oracle Primavera Unifier", port:port);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "16.1.0.0", "fixed_version" : "16.2.15.7" },
  { "min_version" : "17.7.0.0", "fixed_version" : "17.12.10" },
  { "min_version" : "18.8.0.0", "fixed_version" : "18.8.6" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE); 
