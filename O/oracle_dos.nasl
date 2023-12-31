#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10808);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2002-0102");
  script_bugtraq_id(3760, 3762);

  script_name(english:"Oracle Application Server Web Cache Multiple Remote DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote host an application that is affected by a denial
of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the version of OracleWebCache
installed on the remote host is affected by denial of
service vulnerability. A remote attacker may exploit 
this vulnerability to crash the remote service.");
  script_set_attribute(attribute:"solution", value:
"Contact your vendor for the latest software release.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/11/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server_web_cache");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2001-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "proxy_use.nasl");
  script_require_ports(1100, 4000, 4001, 4002, "Services/www");

  exit(0);
}

#
# Code Starts Here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:1100);
ports = add_port_in_list(list:ports, port:4000);
ports = add_port_in_list(list:ports, port:4001);
ports = add_port_in_list(list:ports, port:4002);

foreach port (ports)
{
data = get_http_banner(port:port);
if(egrep(pattern:".*Oracle9iAS Web Cache/2\.0\.0\.[012].*",
	  string:data))security_warning(port);
}
