#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76362);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-3432", "CVE-2014-3433");
  script_bugtraq_id(68160, 68161);
  script_xref(name:"IAVB", value:"2014-B-0087");

  script_name(english:"Symantec Data Insight < 4.5 Multiple Vulnerabilities (SYM14-012)");
  script_summary(english:"Checks the Data Insight version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Symantec Data Insight prior to
4.5. It is, therefore, affected by multiple vulnerabilities :

  - The management console for Symantec Data Insight is
    affected by a cross-site scripting vulnerability due to
    a failure to sanitize user-supplied input.
    (CVE-2014-3432)

  - The management console for Symantec Data Insight is
    affected by an HTML injection vulnerability due to a
    failure to sanitize user-supplied input.
    (CVE-2014-3433)");
  # https://support.symantec.com/en_US/article.SYMSA1299.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a6c1fa3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Data Insight 4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3433");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:data_insight");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_data_insight_detect.nbin");
  script_require_keys("installed_sw/Symantec Data Insight Management Console");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

get_kb_item_or_exit("installed_sw/Symantec Data Insight Management Console");
app_name = "Symantec Data Insight Management Console";
port = get_http_port(default:443);

installs = get_installs(app_name:app_name, port:port);
if (installs[0] == IF_NOT_FOUND) audit(AUDIT_WEB_APP_NOT_INST, app_name, port);

install = branch(installs[1]);
url = build_url(qs:install['path'], port:port);
version = install['version'];

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, app_name, url);

fix = "4.5";
if (version =~ "^[34]\." && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);
