#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101899);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id("CVE-2015-0254", "CVE-2016-6814");
  script_bugtraq_id(72809, 95429);
  script_xref(name:"CERT", value:"576313");

  script_name(english:"Oracle Primavera Gateway Multiple Vulnerabilities (July 2017 CPU)");
  script_summary(english:"Checks the version of Oracle Primavera Gateway.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera
Gateway installation running on the remote web server is prior to
14.2.3, 15.x prior to 15.2.12, or 16.x prior to 16.2.4. It is,
therefore, affected by the following vulnerabilities :

  - A remote code execution vulnerability exists in the
    Primavera Integration (Standard) component, specifically
    in Apache Standard Taglib, due to an XML external entity
    (XXE) injection flaw when parsing XML data because of an
    incorrectly configured XML parser accepting XML external
    entities from untrusted sources. An unauthenticated,
    remote attacker can exploit this, via specially crafted
    XML data, to disclose resources on the target system or
    utilize XSLT extensions to execute arbitrary code.
    (CVE-2015-0254)

  - A remote code execution vulnerability exists in the
    Primavera Integration (Groovy) component due to unsafe
    deserialize calls of unauthenticated Java objects to the
    Apache Commons Collections (ACC) library. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code on the target host.
    (CVE-2016-6814)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76f5def7");
  # https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c6d83db");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Primavera Gateway version 14.2.3 / 15.2.12 / 16.2.4
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6814");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_gateway.nbin");
  script_require_keys("installed_sw/Oracle Primavera Gateway");
  script_require_ports("Services/www", 8006);

  exit(0);
}

include("http.inc");
include("vcf.inc");

get_install_count(app_name:"Oracle Primavera Gateway", exit_if_zero:TRUE);

port = get_http_port(default:8006);

app_info = vcf::get_app_info(app:"Oracle Primavera Gateway", port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "max_version" : "14.2.3", "fixed_version" : "14.2.3" },
  { "min_version" : "15.0.0", "max_version" : "15.2.12", "fixed_version" : "15.2.12" },
  { "min_version" : "16.0.0", "max_version" : "16.2.5", "fixed_version" : "16.2.5" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE); 
