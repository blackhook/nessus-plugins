#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108542);
  script_version("1.4");
  script_cvs_date("Date: 2018/08/07 11:56:11");

  script_cve_id("CVE-2007-5066");
  script_bugtraq_id(25773);

  script_name(english:"Webmin Unspecified Command Execution Vulnerability (< 1.370)");
  script_summary(english:"Checks the version of Webmin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Webmin installed on the remote host is older than
1.370. It is therefore affected by an unspecified vulnerability that
allows remote authenticated users to execute arbitrary commands via a
crafted URL, provided the host operating system is Windows. Note that
Nessus has relied on the self-reported version of the software from
either the index page or the Server header.");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/changes-1.370.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Webmin version 1.370 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webmin:webmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("webmin.nasl");
  script_require_keys("www/webmin");
  script_require_ports("Services/www", 10000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'Webmin';
port = get_http_port(default:10000, embedded: TRUE);
version = get_kb_item_or_exit('www/webmin/'+port+'/version');
url = build_url(port:port, qs:'/');
fix = "1.370";

if (ver_compare(fix:"1.370", ver:version, strict:FALSE) == -1)
{
  security_report_v4(
    severity:SECURITY_HOLE,
    port:port,
    extra:
      '\n' + '  URL              : ' + url +
      '\n' + '  Reported version : ' + version +
      '\n' + '  Fixed version    : ' + fix +
      '\n'
  );
}
else
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);
}
