#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20178);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-3483");
  script_bugtraq_id(15285);

  script_name(english:"GO-Global for Windows _USERSA_ Remote Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote display server is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of the GO-Global
remote display server that fills a small buffer with user-supplied
data without first checking its size.  An attacker can leverage this
issue to overflow the buffer, causing the server to crash and possibly
even allowing for arbitrary code execution on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2005/Nov/78");
  script_set_attribute(attribute:"solution", value:
"Upgrade to GO-Global version 3.1.0.3281 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:graphon:go-global");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("go_global_detect.nasl");
  script_require_ports("Services/go-global", 491);

  exit(0);
}

include ("byte_func.inc");

port = get_kb_item("Services/go-global");
if (!port)
  exit (0);

if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);

req = "_USERSA_";
send(socket:soc, data:req);

res = recv(socket:soc, length:8, min:8);
if (req >!< res)
  exit (0);

# A patched version does not accept challenge larger than 0x80, so we send 0x81 ;-)
req = raw_string(
  0x00, 0x81,
  0xF9, 0x42, 0x88, 0x1C, 0x81, 0x19, 0x68, 0x10, 0xF7, 0x39, 0x9A, 0x11, 0xA4, 0xDD, 0x1A, 0xFB, 0xD2, 0xFF, 0xC2, 0x35, 0x76, 0xBF, 0x47, 0x5B, 0x67, 0xD4, 0xFA, 0x2E, 0xAB, 0x49, 0x4E, 0x3F, 0x33, 0x7F, 0x98, 0x01, 0x47, 0x1D, 0x7A, 0x3A, 0x6C, 0x6F, 0xBD, 0x89, 0xEC, 0x89, 0xBC, 0x33, 0x1D, 0xB7, 0x8E, 0xEE, 0xF6, 0x4D, 0xA4, 0x5B, 0x73, 0x47, 0x68, 0x97, 0xD9, 0x39, 0xC6, 0x59, 
  0xF9, 0x42, 0x88, 0x1C, 0x81, 0x19, 0x68, 0x10, 0xF7, 0x39, 0x9A, 0x11, 0xA4, 0xDD, 0x1A, 0xFB, 0xD2, 0xFF, 0xC2, 0x35, 0x76, 0xBF, 0x47, 0x5B, 0x67, 0xD4, 0xFA, 0x2E, 0xAB, 0x49, 0x4E, 0x3F, 0x33, 0x7F, 0x98, 0x01, 0x47, 0x1D, 0x7A, 0x3A, 0x6C, 0x6F, 0xBD, 0x89, 0xEC, 0x89, 0xBC, 0x33, 0x1D, 0xB7, 0x8E, 0xEE, 0xF6, 0x4D, 0xA4, 0x5B, 0x73, 0x47, 0x68, 0x97, 0xD9, 0x39, 0xC6, 0x59,
  0xF9,
  0x00, 0x01, 0x11
);

send(socket:soc, data:req);

# A vulnerable version replies with 2 response (each same size as the challenge)

len = recv(socket:soc, length:2, min:2);
if (isnull(len))
  exit (0);

len = getword (blob:len, pos:0);
if (len != 0x81)
  exit (0);

buf = recv(socket:soc, length:len, min:len);
if (strlen(buf) != len)
  exit (0);

len = recv(socket:soc, length:2, min:2);
if (isnull(len))
  exit (0);

len = getword (blob:len, pos:0);
if (len != 0x81)
  exit (0);

buf = recv(socket:soc, length:len, min:len);
if (strlen(buf) != len)
  exit (0);

security_hole(port);
