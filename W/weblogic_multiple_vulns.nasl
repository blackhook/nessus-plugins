#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14722);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-2320");
  script_bugtraq_id(11168);
  script_xref(name:"CERT", value:"867593");

  script_name(english:"WebLogic < 8.1 SP3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple flaws.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server is BEA WebLogic version
8.1 SP2 or older.  There are multiple vulnerabilities in such versions
that may allow unauthorized access on the remote host or to get the
content of the remote JSP scripts.");
  script_set_attribute(attribute:"see_also", value:"https://securitytracker.com/id/1008866");
  script_set_attribute(attribute:"solution", value:
"Apply Service Pack 3 on WebLogic 8.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("weblogic_detect.nasl");
  script_require_keys("www/weblogic");
  script_require_ports("Services/www", 80, 7001);

  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("http.inc");

appname = "WebLogic";
get_kb_item_or_exit("www/weblogic");
port = get_http_port(default:80);
version = get_kb_item_or_exit("www/weblogic/" + port + "/version");
banner = get_http_banner(port:port);

if (!banner || "WebLogic " >!< banner) audit(AUDIT_INST_VER_NOT_VULN, appname, version);

vuln = FALSE;
pat = "^Server:.*WebLogic .*([0-9]+\.[0-9.]+) ";
matches = egrep(pattern:pat, string:banner);
if (matches) {
  foreach match (split(matches)) {
    match = chomp(match);
    ver = eregmatch(pattern:pat, string:match);
    if (!isnull(ver)) {
      # Extract the version and service pack numbers.
      nums = split(ver[1], sep:".", keep:FALSE);
      ver_maj = int(nums[0]);
      ver_min = int(nums[1]);

      sp = ereg_replace(
        string:match, 
        pattern:".* (Service Pack |SP)([0-9]+) .+",
        replace:"\2"
      );
      if (!sp) sp = 0;
      else sp = int(sp);

      # Check them against vulnerable versions listed in BEA's advisories.
      if (
        # version 6.x
        (
          ver_maj == 6 && 
          (
            ver_min < 1 ||
            (ver_min == 1 && sp <= 6)
          )
        ) ||

        # version 7.x
        (ver_maj == 7 && (ver_min == 0 && sp <= 5)) ||
  
        # version 8.x
        (
          ver_maj == 8 && 
          (
            ver_min < 1 ||
            (ver_min == 1 && sp <= 2)
          )
        )
      ) vuln = TRUE;
    }
  }
}

if (vuln)
{
  security_hole(port);
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, appname, version);
