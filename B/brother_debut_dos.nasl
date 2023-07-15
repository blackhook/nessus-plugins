#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104900);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-16249");

  script_name(english:"Brother Printer Debut embedded httpd <= 1.20 DoS");
  script_summary(english:"Checks the version of Brother Debut web server.");

  script_set_attribute(attribute:"synopsis", value:
"The embedded HTTP server running on the Brother printer is affected 
by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the 
embedded Debut HTTP server running on the remote Brother printer is
equal or prior to version 1.20. It is, therefore, affected by a 
denial of service vulnerability.");
  # https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2017-017/?fid=10211
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?661aae0c");
  script_set_attribute(attribute:"solution", value:
"Refer to the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("brother_debut_detect.nbin");
  script_require_keys("www/brother_debut");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

app = "Brother Printer Debut HTTP Server";
port = get_http_port(default:80);

# Make sure this is Brother Debut
get_kb_item_or_exit('www/'+port+'/brother_debut');

# Check if we could get a version
version   = get_kb_item_or_exit('www/'+port+'/brother_debut/version', exit_code:1);
if (version == "unknown") audit(AUDIT_UNKNOWN_APP_VER, app);
max_version = "1.20";

if (ver_compare(ver:version, fix:max_version) <= 0)
{
  report =
    '\n  Installed version : ' + version;

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_HOST_NOT, "affected");
