#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10951);
  script_version("1.37");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2002-0033", "CVE-2002-0084");
  script_bugtraq_id(4631, 4674);
  script_xref(name:"CERT", value:"161931");
  script_xref(name:"CERT", value:"635811");
  script_xref(name:"CERT-CC", value:"CA-2002-11");
  script_xref(name:"EDB-ID", value:"21437");

  script_name(english:"Solaris cachefsd Multiple Vulnerabilities (ESCROWUPGRADE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote RPC service is potentially affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The cachefsd RPC service is running on the remote host. It is,
therefore, potentially affected by the following vulnerabilities :

  - A heap-based buffer overflow condition exists in the
   cfsd_calloc() function that allows an unauthenticated,
   remote attacker to execute arbitrary code via a long
   directory and cache name. (CVE-2002-0033 / ESCROWUPGRADE)

  - A heap-based buffer overflow condition exists in the
   fscache_setup() function that allows a local attacker
   to gain root privileges via a long mount argument.
   (CVE-2002-0084)

ESCROWUPGRADE is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/08 by a group known as the Shadow
Brokers.

Note that Nessus has not attempted to exploit these issues but has
instead only detected that the service is running.");
  # https://web.archive.org/web/20020616080638/http://archives.neohapsis.com/archives/vulnwatch/2002-q2/0048.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?082477b0");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1000988.1.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor's advisory.

Alternatively, disable cachefsd by commenting out cachefsd in
/etc/inetd.conf and then killing the process.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/05/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2002-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rpc_portmap.nasl");
  script_require_keys("rpc/portmap", "Settings/ParanoidReport", "Host/OS");

  exit(0);
}

include("misc_func.inc");
include("global_settings.inc");
include("sunrpc_func.inc");
include("audit.inc");

os = get_kb_item_or_exit("Host/OS");
if ("Solaris" >!< os) audit(AUDIT_OS_NOT, "Solaris");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

#
# This is kinda lame but there's no way (yet) to remotely determine if
# this service is vulnerable to this flaw.
#
RPC_PROG = 100235;
tcp = 0;
port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
   port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_TCP);
   tcp = 1;
   }

if(port)
{
 if(tcp)security_hole(port);
 else security_hole(port:port, protocol:"udp");
}
