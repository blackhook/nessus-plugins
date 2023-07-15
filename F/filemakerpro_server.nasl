#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(11586);
  script_version ("1.18");
  script_bugtraq_id(7315);

  script_name(english:"FileMaker Pro Client Request User Passwords Remote Disclosure");
  script_summary(english: "connects to port 49727 and says 'hello'");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote service has an information disclosure vulnerability."
  );
  script_set_attribute( attribute:"description",  value:
"The remote host is running a FileMakerPro server.

There is a flaw in the design of the FileMakerPro server which
makes the database authentication occur on the client side.
A remote attacker could exploit this flaw to gain access to
databases by connecting to this port with a rogue client."  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://seclists.org/bugtraq/2003/Apr/171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.filemaker.com/s/?language=en_US"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to the latest version of FileMaker Pro."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/07");
 script_cvs_date("Date: 2018/11/15 20:50:23");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english: "This script is (C) 2003-2018 Tenable Network Security, Inc.");

  script_dependencie("find_service1.nasl");
  script_require_ports(5003);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = 5003;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 send(socket:soc, data:raw_string(0x00, 0x04, 0x13, 0x00));
 r = recv(socket:soc, length:3);
 if(r == raw_string(0x00, 0x06, 0x14)){
  register_service(port:port, proto:"filemakerpro-server");
  security_hole(port);
 }
}

