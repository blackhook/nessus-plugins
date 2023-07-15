#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26192);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2000-0818");
  script_bugtraq_id(1853);

  script_name(english:"Oracle Listener Program Logging Privilege Escalation (1361722)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database service allows arbitrary code execution.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Oracle listener program (tnslsnr)
on the remote host has a problem with the 'SET TRC_FILE' and 'SET
LOG_FILE' commands.  An attacker can leverage this issue to log
arbitrary data to arbitrary files subject to the permissions under
which the listener program operates, corrupting existing files or
creating new ones. 

In addition, it is also subject to attacks that can shut down or crash
the listener.");
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20080404173741/http://xforce.iss.net:80/xforce/alerts/id/advise66");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technology/deploy/security/pdf/listener_alert.pdf");
  script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2000/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:listener");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2007-2022 Tenable Network Security, Inc.");

  script_dependencies("oracle_tnslsnr_version.nasl");
  script_require_ports("Services/oracle_tnslsnr", 1521);

  exit(0);
}


include("global_settings.inc");


# nb: don't run if the user wants to avoid false alarms.
if (report_paranoia < 1) exit(0);


port = get_kb_item("Services/oracle_tnslsnr");
if (!get_port_state(port)) exit(0);


# Check the version.
#
# nb: if you believe Oracle, only 7.3.4, 8.0.6, and 8.1.6 are vulnerable.
#     TNSLSNR for Solaris: Version 8.1.6.0.0 - Production
ver = get_kb_item("oracle_tnslsnr/" + port + "/version");
if (ver)
{
  if (ereg(pattern:".*Version\ (8\.1\.6)|(8\.0\.6)|(7\.3\.4).*.", string:ver))
  {
    report = string(
      "The remote Oracle Listener Program reports itself as :\n",
      "\n",
      "  ", ver
    );
    security_hole(port:port, extra:report);
  }
}

