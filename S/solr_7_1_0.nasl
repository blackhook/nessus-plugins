#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104353);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-12629");
  script_bugtraq_id(101261);
  script_xref(name:"IAVA", value:"2017-A-0319");

  script_name(english:"Apache Solr 5.x < 5.5.5 / 6.x < 6.6.2 / 7.x < 7.1.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Solr");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Solr running on the remote web server is
affected by multiple vulnerabilities as referenced in the advisory.");
  script_set_attribute(attribute:"see_also", value:"http://lucene.apache.org/solr/news.html");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2017/q4/105");
  # https://lucene.apache.org/core/5_5_5/changes/Changes.html#v5.5.5.bug_fixes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?552cc7b7");
  # https://lucene.apache.org/core/5_5_5/changes/Changes.html#v5.5.5.bug_fixeshttps://lucene.apache.org/core/6_6_2/changes/Changes.html#v6.6.2.bug_fixes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15df27f7");
  # https://lucene.apache.org/core/5_5_5/changes/Changes.html#v5.5.5.bug_fixeshttps://lucene.apache.org/core/6_6_2/changes/Changes.html#v6.6.2.bug_fixeshttps://lucene.apache.org/core/7_1_0/changes/Changes.html#v7.1.0.bug_fixes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f91188b1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Solr version 5.5.5 / 6.6.2 / 7.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:solr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solr_detect.nbin");
  script_require_keys("installed_sw/Apache Solr");
  script_require_ports("Services/www", 8983);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "Apache Solr";
get_install_count(app_name:app,exit_if_zero:TRUE);
port    = get_http_port(default:8983);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {"min_version" : "5.5.0",  "max_version" : "5.5.4", "fixed_version" : "5.5.5" },
  {"min_version" : "6.0.0",  "max_version" : "6.6.1", "fixed_version" : "6.6.2" },
  {"min_version" : "7.0.0",  "max_version" : "7.0.1", "fixed_version" : "7.1.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
