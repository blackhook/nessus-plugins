#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62976);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2012-4729");
  script_bugtraq_id(55847);

  script_name(english:"Wing FTP Server Multiple ZIP Commands Parsing Remote DoS");
  script_summary(english:"Checks version of Wing FTP");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP service is vulnerable to an authenticated denial of
service attack.");
  script_set_attribute(attribute:"description", value:
"The remote FTP server is running a version of Wing FTP Server earlier
than 4.1.1.  As such, it is reportedly affected by an authenticated
denial of service attack triggered when parsing multiple ZIP
commands.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2012/Oct/49");
  script_set_attribute(attribute:"see_also", value:"https://www.wftpserver.com/serverhistory.htm#gotop");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4729");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wftpserver:wing_ftp_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wing_ftp_server_detect.nasl");
  script_require_keys("SMB/Wing_FTP/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Wing_FTP/Version");
path = get_kb_item_or_exit("SMB/Wing_FTP/Path");

# Check if the version is vulnerable.
fixed = "4.1.1";

if (ver_compare(ver:version, fix:fixed, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n'; 
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
} 
else audit(AUDIT_INST_PATH_NOT_VULN, "Wing FTP", version, path);
