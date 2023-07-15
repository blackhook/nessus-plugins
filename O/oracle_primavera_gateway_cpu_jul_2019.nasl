#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126828);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2018-15756",
    "CVE-2018-19360",
    "CVE-2018-19361",
    "CVE-2018-19362"
  );
  script_bugtraq_id(105703, 107985);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Primavera Gateway Multiple Vulnerabilities (Jul 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera
Gateway installation running on the remote web server is 15.x prior to 
15.2.16, 16.x prior to 16.2.9, 17.x prior to 17.12.4, or 18.x prior to
18.8.6. It is, therefore, affected by multiple vulnerabilities:

  - An unspecified vulnerability in the Spring Framework,
    version 5.1, versions 5.0.x prior to 5.0.10, versions
    4.3.x prior to 4.3.20, and older unsupported versions
    on the 4.2.x branch allows an a malicious user to add
    a range header with a high number of ranges, or with
    wide ranges that overlap, or both, to cause a denial
    of service. (CVE-2018-15756)

  - FasterXML jackson-databind 2.x before 2.9.8 might allow
    attackers to have unspecified impact by leveraging
    failure to block the axis2-transport-jms class from
    polymorphic deserialization. (CVE-2018-19360)

  - FasterXML jackson-databind 2.x before 2.9.8 might allow
    attackers to have unspecified impact by leveraging
    failure to block the openjpa class from polymorphic
    deserialization. (CVE-2018-19361)

  - FasterXML jackson-databind 2.x before 2.9.8 might allow
    attackers to have unspecified impact by leveraging
    failure to block the jboss-common-core class from
    polymorphic deserialization. (CVE-2018-19362)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html#AppendixPVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25a1b782");
  # https://support.oracle.com/rs?type=doc&id=2555549.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5f18b61");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Primavera Gateway version 15.2.16 / 16.2.9 / 17.12.4
/ 18.8.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19362");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_gateway.nbin");
  script_require_keys("installed_sw/Oracle Primavera Gateway");
  script_require_ports("Services/www", 8006);

  exit(0);
}

include('http.inc');
include('vcf.inc');

get_install_count(app_name:'Oracle Primavera Gateway', exit_if_zero:TRUE);

port = get_http_port(default:8006);

app_info = vcf::get_app_info(app:'Oracle Primavera Gateway', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '15.0.0', 'fixed_version' : '15.2.16' },
  { 'min_version' : '16.0.0', 'fixed_version' : '16.2.9' },
  { 'min_version' : '17.0.0', 'fixed_version' : '17.12.4' },
  { 'min_version' : '18.0.0', 'fixed_version' : '18.8.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE); 
