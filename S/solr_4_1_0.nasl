#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71844);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-6612", "CVE-2013-6407");
  script_bugtraq_id(64008, 64427);

  script_name(english:"Apache Solr < 4.1.0 Multiple XML External Entity Injections");
  script_summary(english:"Checks version of Apache Solr.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by
multiple XML External Entity (XXE) injection vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Solr running on the remote web server is
affected by multiple XML external entity injection vulnerabilities
because the XML parser accepts XML data containing external entity
declarations from untrusted sources. A remote, unauthenticated
attacker can exploit this flaw to gain access to arbitrary files or to
cause a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/SOLR-3895");
  script_set_attribute(attribute:"see_also", value:"http://lucene.apache.org/solr/4_1_0/changes/Changes.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Solr version 4.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:solr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2021 Tenable Network Security, Inc.");

  script_dependencies("solr_detect.nbin");
  script_require_keys("installed_sw/Apache Solr");
  script_require_ports("Services/www", 8983);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "Apache Solr";
get_install_count(app_name:appname,exit_if_zero:TRUE);
port    = get_http_port(default:8983);
install = get_single_install(
  app_name:appname,
  port:port, 
  exit_if_unknown_ver:TRUE
);

dir         = install["path"];
version     = install["version"];
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, install_url);

if (ver_compare(ver:version,fix:"4.1.0",strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 4.1.0\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
