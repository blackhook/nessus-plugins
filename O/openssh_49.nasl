#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(44079);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/15 20:50:23");

  script_cve_id("CVE-2008-1657");
  script_bugtraq_id(28531);

  script_name(english:"OpenSSH < 4.9 'ForceCommand' Directive Bypass");
  script_summary(english:"Checks OpenSSH server version");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH installed on the
remote host is earlier than 4.9.  It may allow a remote, authenticated
user to bypass the 'sshd_config' 'ForceCommand' directive by modifying
the '.ssh/rc' session file.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-4.9");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH version 4.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");

  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
 
  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"ssh", exit_on_fail:TRUE);

banner = get_kb_item_or_exit("SSH/banner/"+port);
bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) exit(1, "The banner from the OpenSSH server on port "+port+" indicates patches may have been backported.");

# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) exit(1, "Could not parse the version string in the banner from port "+port+".");
version = match[1];

match = eregmatch(string:version, pattern:'^([0-9.]+)');
if (isnull(match)) # this should never happen due to the previous eregmatch() call, but let's code defensively anyway
  exit(1, 'Failed to parse the version (' + version + ') of the service listening on port '+port+'.');

ver = match[1];
fix = '4.9';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The OpenSSH server on port "+port+" is not affected as it's version "+version+".");

