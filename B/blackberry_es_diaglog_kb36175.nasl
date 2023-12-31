#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77327);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id("CVE-2014-1469");
  script_bugtraq_id(69211);

  script_name(english:"BlackBerry Enterprise Server / Enterprise Service / Enterprise Server Express Information Disclosure (KB36175)");
  script_summary(english:"Checks version");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of BlackBerry Enterprise Server on the remote host
contains an information disclosure flaw pertaining to the logging of
session management exceptions. By gaining access to certain diagnostic
logs, an authenticated attacker could discover logged credentials and
use them to impersonate a valid user.");
  script_set_attribute(attribute:"see_also", value:"https://salesforce.services.blackberry.com/kbredirect/KB36175");
  script_set_attribute(attribute:"solution", value:
"Apply the vendor-supplied patches.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1469");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:blackberry:enterprise_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:blackberry:enterprise_server_express");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:blackberry:blackberry_enterprise_service");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("blackberry_es_installed.nasl", "smb_hotfixes.nasl");
  script_require_keys("installed_sw/BlackBerry Enterprise Service", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("bsal.inc");
include("byte_func.inc");
include("install_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("zip.inc");

# Patched BAS jar file, basSystemServer.jar, contains
# a file pom.properties that contains a creation date.
# Get that date string and return it along with a
# converted version of it (use for comparison).
# Return is NULL if there are any issues, otherwise,
# return is an array containing the items noted above.
function get_pom_date(path)
{
  local_var pom_date, matches, lines, line, month_integer;
  local_var fh, name, port, login, pass, domain, rc;
  local_var soc, share, dir, date_pat, pom_file;

  fh = CreateFile(
    file:path,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    pom_file = zip_parse(smb:fh, "META-INF/maven/com.rim.bes.bas/bas.server.managementServer/pom.properties");
    CloseFile(handle:fh);
  }

  if (isnull(pom_file)) return NULL;

  # Extract date string from pom.properties file.
  if ("#Generated by Maven" >< pom_file)
  {
    date_pat = "^#(Mon|Tue|Wed|Th|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9]+) ([0-9][0-9]:[0-9][0-9]:[0-9][0-9]) [A-Z][A-Z][A-Z] ([12][0-9][0-9][0-9])";

    # "#Dow Mon DD HH:MM:SS {zone} YYYY"
    line = egrep(string:pom_file, pattern:date_pat);

    if (!(line)) return NULL;
  }
  else return NULL;

  matches = pregmatch(string:line, pattern:date_pat);
  if (isnull(matches)) return NULL;

  month_integer = make_array("Jan", "01", "Feb", "02", "Mar", "03", "Apr", "04", "May", "05", "Jun", "06", "Jul", "07", "Aug", "08", "Sep", "09", "Oct", "10", "Nov", "11", "Dec", "12");

  pom_date = matches[5] +                  # YYYY
             month_integer[matches[2]] +   # MM
             matches[3] +                  # DD
             matches[4];                   # HH:MM:SS
  pom_date = str_replace(string:pom_date, find:":", replace:"");

  # YYYYMMDDHHMMSS
  return make_array(
    'date_string', str_replace(string:matches[0], find:"#", replace:""),
    'date_converted', pom_date
  );
}

#
# Plugin code starts here
#
app = 'BlackBerry Enterprise Service';

get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

prod     = install['Product'];
version  = install['version'];
base_dir = install['path'];

BES5  = FALSE;
BES10 = FALSE;
BES_EXPRESS = FALSE;

vuln_version = 0;
check_bas_jar = FALSE;

# Enterprise Server and Express
if (
  "Enterprise Server" >< prod &&
  version =~ "^5\.0"
)
{
  if (
    ("Microsoft Exchange" >< prod || "IBM Lotus Domino" >< prod || "Novell GroupWise" >< prod)
    && "Express" >!< prod
  ) BES5 = TRUE;

  if (
    ("Microsoft Exchange" >< prod || "IBM Lotus Domino" >< prod)
    && "Express" >< prod
  ) BES_EXPRESS = TRUE;
}

# Enterprise Service 10.x before 10.2.2
else if ("Enterprise Service" >< prod && version =~ "^10\.") BES10 = TRUE;
else audit(AUDIT_NOT_INST, "BlackBerry Enterprise Server 5.x / Enterprise Service 10.x / Enterprise Server Express 5.x for Microsoft Exchange or IBM Lotus Domino");

get_kb_item_or_exit("SMB/Registry/Enumerated");

#
# Enterprise Service 10.x
#
if (BES10)
{
  # Do not need to check files for BES10 (10.2.2 is the fix)
  fixed_version = "10.2.2";
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
    vuln_version = version;
}

#
# Enterprise Server 5.x < 5.0.4 MR 7
#
if (BES5)
{
  # We do not need to do a file check for BES5 (5.0.4 MR 7 is the fix)
  if (
    version =~ "^5\.0\.([0-3]|4 MR [0-6])($|[^0-9])"
  )
  {
    vuln_version = version;
    fixed_version = "5.0.4 MR 7";
  }
}

#
# Enterprise Server Express 5.0.4 with Interim Fix
#
if (BES_EXPRESS)
{
  if (
    version =~ "^5\.0\.[0-3]($|[^0-9])"
  )
  {
    vuln_version = version;
    fixed_version = "5.0.4 with Interim Security Update for 12 AUG 2014";
  }
  else
  {
    # Will need to check files
    check_bas_jar = TRUE;
    fixed_pom_date_converted = "20140610155610";
    fixed_pom_date_string = "Wed Jun 10 15:56:10 EDT 2014";
    fixed_version = "5.0.4 with Interim Security Update for 12 AUG 2014";
  }
}

extra_info = "";

# Need to check on actual file contents for
# interim fix because there aren't any good
# file version changes. This only needs to
# take place if the product version is at
# the highest patched level before the
# fix.
if (check_bas_jar)
{
  name    =  kb_smb_name();
  port    =  kb_smb_transport();
  if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  # Try to connect to server.
  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);
  session_init(socket:soc, hostname:name, report_access:TRUE);

  share = ereg_replace(string:base_dir, pattern:"^([A-Za-z]):.*", replace:"\1$");
  dir = ereg_replace(string:base_dir, pattern:"^[A-Za-z]:(.*)", replace:"\1");
  NetUseDel(close:FALSE);

  # Connect to the share software is installed on.
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  # Check basServerUtility.jar patch
  path = dir + "\BAS\lib\basServerUtility.jar";
  pom_date = get_pom_date(path:path);

  NetUseDel();

  if (!isnull(pom_date))
  {
    if (pom_date['date_converted'] < fixed_pom_date_converted)
    {
      vuln_version = version;
      extra_info +=
        '\nBased on its creation date, ' +
        base_dir + "\BAS\lib\basServerUtility.jar" +
        ', needs to be updated.' +
        '\n' +
        '\n  Installed creation date : ' + pom_date['date_string'] +
        '\n  Fixed creation date     : ' + fixed_pom_date_string +
        '\n';
    }
  }
  else exit(1, "There was an error retriveing the creation date of " + path + ".");
}

if (vuln_version)
{
  port = kb_smb_transport();
  if (report_verbosity > 0)
  {

    report =
      '\n  Prod              : ' + prod +
      '\n  Path              : ' + base_dir +
      '\n  Installed version : ' + vuln_version;

    if (fixed_version) report +=
      '\n  Fixed version     : ' + fixed_version;

    if (extra_info) report += '\n' + extra_info;

    if (BES_EXPRESS) report +=
      '\nInstall Interim Security Update for August 12, 2014' +
      '\nto correct the issue.' +
      '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, prod, version, base_dir);
