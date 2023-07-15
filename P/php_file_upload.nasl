#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10513);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2000-0860");
  script_bugtraq_id(1649);

  script_name(english:"PHP File Upload Capability Hidden Form Field Modification Arbitrary File Access");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote host.");
  script_set_attribute(attribute:"description", value:
"A version of PHP that is older than 3.0.17 or 4.0.3 is running on this
host.

If a PHP service that allows users to upload files and then display their
content is running on this host, an attacker may be able to read arbitrary
files from the server.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/manual/en/language.variables.predefined.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 3.0.17 or 4.0.3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/09/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2000-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

 banner = get_http_banner(port:port);
 if(!banner)exit(0);
 if(egrep(pattern:"(.*PHP/3\.0\.((1[0-6])|([0-9]([^0-9]|$))))|(.*PHP/4\.0\.[0-2]([^0-9]|$))",
          string:banner))
 {
   security_warning(port);
 }
