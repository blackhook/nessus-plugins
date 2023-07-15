#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100634);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Redis Server Unprotected by Password Authentication");

  script_set_attribute(attribute:"synopsis", value:
"A Redis server is not protected by password authentication.");
  script_set_attribute(attribute:"description", value:
"The Redis server running on the remote host is not protected by
password authentication. A remote attacker can exploit this to gain
unauthorized access to the server.");
  script_set_attribute(attribute:"see_also", value:"https://redis.io/commands/auth");
  script_set_attribute(attribute:"solution", value:
"Enable the 'requirepass' directive in the redis.conf configuration
file.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pivotal_software:redis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("redis_detect.nbin");
  script_require_ports("Services/redis_server", 6379);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"redis_server", default:6379, exit_on_fail:TRUE);
res = get_kb_item_or_exit("redis/" + port + "/PasswordProtected");

if(!res)
{
  report = '\nAn unauthenticated INFO request to the Redis Server returned the following:\n\n' +
  get_kb_item("redis/" + port + "/INFO") + '\n';
  security_hole(port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Redis Server", port);
