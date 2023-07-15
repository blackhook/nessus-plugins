#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103504);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-9803");
  script_bugtraq_id(100870);

  script_name(english:"Apache Solr < 6.6.1 Kerberos Plugin Delegation Token Handling Remote Information Disclosure");
  script_summary(english:"Checks version of Solr");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by
a remote information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Solr running on the remote web server is
affected by a flaw in the Kerberos plugin due to an issue when
handling delegation tokens. An authenticated attacker may be able to
obtain sensitive information.");
  # http://mail-archives.us.apache.org/mod_mbox/www-announce/201709.mbox/%3CCAOOKt53AOScg04zUh0%2BR_fcXD0C9s5mQ-OzdgYdnHz49u1KmXw@mail.gmail.com%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95620204");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/SOLR-11184");
  script_set_attribute(attribute:"see_also", value:"http://lucene.apache.org/solr/6_6_1/changes/Changes.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Solr version 6.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9803");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:solr");
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
  {"min_version" : "6.2.0",  "max_version" : "6.6.0", "fixed_version" : "6.6.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
