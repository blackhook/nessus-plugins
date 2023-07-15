#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76369);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(67826);

  script_name(english:"Serv-U FTP Server < 15.1.0.458 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the installed version of Serv-U is a version
prior to 15.1.0.458. It is, therefore, affected by a cross-site
scripting vulnerability, an information-disclosure vulnerability, and
multiple unspecified security vulnerabilities.");
  # https://support.solarwinds.com/Success_Center/Serv-U_Managed_File_Transfer_Serv-U_FTP_Server/Serv-U_Documentation/release_notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?609e48a8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Serv-U 15.1.0.458 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:serv-u:serv-u");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("servu_version.nasl");
  script_require_keys("ftp/servu");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

port    = get_ftp_port(default:21);
version = get_kb_item_or_exit('ftp/'+port+'/servu/version');
source  = get_kb_item_or_exit('ftp/'+port+'/servu/source');

fixed_version = "15.1.0.458";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source+
      '\n  Installed version : '+version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Serv-U", port, version);
