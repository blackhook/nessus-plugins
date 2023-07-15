#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(10704);
  script_version("1.38");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/21");

  script_cve_id("CVE-2001-0731");
  script_bugtraq_id(3009);
  script_xref(name:"OWASP", value:"OWASP-CM-004");
  script_xref(name:"EDB-ID", value:"21002");

  script_name(english:"Apache Multiviews Arbitrary Directory Listing");
  script_summary(english:"Attempts to find a directory listing.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Apache web server running on the remote host is affected by an
information disclosure vulnerability. An unauthenticated, remote
attacker can exploit this, by sending a crafted request, to display a
listing of a remote directory, even if a valid index file exists in
the directory.

For Apache web server later than 1.3.22, review listing directory
configuration to avoid disclosing sensitive information");
  # https://httpd.apache.org/security/vulnerabilities_13.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f39e976b");
  # https://cwiki.apache.org/confluence/display/httpd/DirectoryListings
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a96611bc");
  # https://httpd.apache.org/docs/2.4/mod/mod_dir.html#directoryindex
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1c382bc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 1.3.22 or later. Alternatively, as a
workaround, disable Multiviews.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2001-0731");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("installed_sw/Apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port);

# Check for dir listing on index
dir_lists = get_kb_list('www/'+port+'/content/directory_index');

# Exit if we've already flagged the directory.
foreach dir_list (dir_lists)
{
  if ("/" >< dir_list)
    exit(0, "A directory listing has already been identified on the web server at "+build_url(qs:dir_list, port:port));
}

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : "/?M=A",
  exit_on_fail : TRUE
);

#added additional check without the exploit, to verify directory listing
res_noexpl = http_send_recv3(
  method : "GET",
  port   : port,
  item   : "/?",
  exit_on_fail : TRUE
);

if (("Index of " >< res[2]) && ("Last modified" >< res[2]) && ("Index of " !~ res_noexpl[2]) && ("Last modified" >< res_noexpl[2]))
{
  output = strstr(res, "Index of");
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
    port         : port,
    generic      : TRUE,
    severity     : SECURITY_WARNING,
    request      : make_list(build_url(qs:"/?M=A", port:port)),
    output       : output
  );
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);