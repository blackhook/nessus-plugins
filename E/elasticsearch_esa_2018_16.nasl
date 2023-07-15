#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118799);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-17244");

  script_name(english:"Elasticsearch ESA-2018-16");
  script_summary(english:"Checks the version of Elasticsearch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Java application that is vulnerable.");
  script_set_attribute(attribute:"description", value:
"Elasticsearch Security versions 6.4.0 to 6.4.2 contain an error in the
way request headers are applied to requests when using the Active
Directory, LDAP, Native, or File realms. A request may receive headers
intended for another request if the same username is being
authenticated concurrently; when used with run as, this can result in
the request running as the incorrect user. This could allow a user to
access information that they should not have access to.");
  # https://www.elastic.co/community/security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f00797e");
  script_set_attribute(attribute:"solution", value:
"Users should upgrade to Elasticsearch version 6.4.3.If upgrading is
not possible setting the realms cache.ttl option to 0 will prevent
caching any user data. This will mitigate this issue but will slow
requests considerably.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17244");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:elasticsearch");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("elasticsearch_detect.nbin");
  script_require_keys("installed_sw/Elasticsearch");
  script_require_ports("Services/www", 9200);

  exit(0);
}

include("audit.inc");
include("http.inc");
include("vcf.inc");

app = "Elasticsearch";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:9200);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { "min_version" : "6.4.0", "fixed_version" : "6.4.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
