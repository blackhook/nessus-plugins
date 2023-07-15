#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(12251);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"RealServer /admin/Docs/default.cfg Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by an information disclosure.");
  script_set_attribute(attribute:"description", value:
"The remote RealServer seems to allow any anonymous user to download the
default.cfg file.  This file is used to store confidential data and
should not be accessible via the web frontend.");
  script_set_attribute(attribute:"solution", value:
"Remove or protect this resource.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/05/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realserver");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/realserver", 7070);

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_service(svc:"realserver", default:7070, exit_on_fail:TRUE);

r = http_send_recv3(method: "GET", item: "/admin/Docs/default.cfg", port:port, exit_on_fail:TRUE);

if (egrep(pattern:".*Please read the configuration section of the manual.*", string:r[0]+r[1]+r[2]))
    security_warning(port);
else audit(AUDIT_HOST_NOT, "affected");
