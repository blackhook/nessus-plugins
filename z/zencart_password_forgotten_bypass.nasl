#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(39501);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-2254", "CVE-2009-2255");
  script_bugtraq_id(35467, 35468);
  script_xref(name:"EDB-ID", value:"9004");
  script_xref(name:"EDB-ID", value:"9005");

  script_name(english:"Zen Cart password_forgotten.php Admin Access Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible to
an authentication bypass.");
  script_set_attribute(attribute:"description", value:
"The version of Zen Cart installed on the remote host is affected by a
design error that allows a remote attacker to bypass authentication and
gain access to the application's admin section by appending
'/password_forgotten.php' to URLs.  Successful exploitation of this
vulnerability may lead to disclosure of sensitive information such as
customer data, SQL injection attacks, or arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://www.zen-cart.com/showthread.php?130161-IMPORTANT-ADMIN-SECURITY-PATCH-security_patch_v138_20090619-zip");
  script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the project's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Zen Cart 1.3.8a File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(89, 287);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zen-cart:zen_cart");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");

  script_dependencies("zencart_detect.nasl");
  script_require_keys("www/zencart");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP");


# Test an install.
install = get_kb_item(string("www/", port, "/zencart"));
if (isnull(install)) exit(0, "Zencart was not detected on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to pull up version info page in the admin control panel.
  url = string(
    dir, "/admin/server_info.php",
    "/password_forgotten.php"
  );

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # If we see the expected contents...
  if (
    'admin/configuration.phyp?gID=' >< res[2] ||
    'TITLE_SERVER_HOST' >< res[2]
  )
  {
    # Unless we're paranoid, make sure we don't normally have access.
    if (report_paranoia < 2)
    {
      url2 = url - "/password_forgotten.php";
      res2 = http_send_recv3(method:"GET", item:url2, port:port);
      if (isnull(res2)) exit(0);

      if (
        'admin/configuration.phyp?gID=' >< res2[2] ||
        'TITLE_SERVER_HOST' >< res2[2]
      ) exit(0);
    }

    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to verify the issue exists using the following URL :\n",
        "\n",
        " ", build_url(port:port, qs:url), "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
