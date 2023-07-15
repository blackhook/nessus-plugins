#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57750);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVA", value:"0001-A-0598");

  script_name(english:"Squid Unsupported Version Detection");
  script_summary(english:"Performs a version check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of a caching proxy
server.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Squid running on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Versions/");
  # https://www.mail-archive.com/squid-users@lists.squid-cache.org/msg01536.html
  script_set_attribute(attribute:"see_also", value:'http://www.nessus.org/u?b3f1e161');
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Squid that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2012-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("squid_version.nasl");
  script_require_ports("Services/http_proxy", 3128, 8080);
  script_require_keys("www/squid", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Build a list of ports from the
list = get_kb_list("http_proxy/*/squid/version");
if (isnull(list)) exit(0, "The host does not appear to be running a Squid proxy server.");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Odd minor versions are dev branches
#
# nb: we don't currently flag branches rated as "old" as OS vendors
#     may still backport patches to them so we should not need to
#     run check 'report_paranoia.'.
eos_dates = make_array(
  "^3\.[2-4]($|\.)" , '2015/01/17',
  "^3\.[01]($|\.)"  , '2012/08/15',
  "^2\.7($|\.)"     , '2012/08/15',
  "^2\.[0-4]($|\.)" , '2002/10/25',
  "^[0-1]\."        , '2001/03/20'
);
withdrawl_announcements = make_array(
  # https://www.mail-archive.com/squid-users@lists.squid-cache.org/msg01536.html
  "^3\.[2-4]($|\.)" , 'http://www.nessus.org/u?b3f1e161',
  "^3\.[01]($|\.)"  , 'http://www.squid-cache.org/mail-archive/squid-users/201208/0168.html',
  "^2\.7($|\.)"     , 'http://www.squid-cache.org/mail-archive/squid-users/201208/0168.html',
  "^2\.[0-4]($|\.)" , 'http://www.mail-archive.com/squid-users@squid-cache.org/msg82793.html',
  "^[0-1]($|\.)"    , 'http://www.mail-archive.com/squid-users@squid-cache.org/msg82793.html'
);

supported_versions = '3.5.x';

obsolete_installs = make_list();
supported_installs = make_list();
foreach item (keys(list))
{
  port = ereg_replace(pattern:'^http_proxy/([0-9]+)/squid/version', replace:'\\1', string:item);
  version = list[item];

  ver = split(version, sep:".", keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);
  version_highlevel = ver[0] + "." + ver[1];

  # Determine support status.
  obsolete = '';
  foreach v (keys(eos_dates))
  {
    if (version_highlevel =~ v)
    {
      obsolete = v;
      break;
    }
  }

  if (obsolete)
  {
    obsolete_installs = make_list(obsolete_installs, version);

    register_unsupported_product(product_name:"Squid",
                                 cpe_base:"squid-cache:squid", version:version);

    info =
      '\n  Source              : ' + get_kb_item_or_exit('http_proxy/'+port+'/squid/source')  +
      '\n  Installed version   : ' + version;

    if (eos_dates[v])
      info += '\n  End of support date : ' + eos_dates[v];
    if (withdrawl_announcements[v])
      info += '\n  Announcement        : ' + withdrawl_announcements[v];
    info += '\n  Supported versions  : ' + supported_versions + '\n';

    security_report_v4(port:port, extra:info, severity:SECURITY_HOLE);
  }
  else supported_installs = make_list(supported_installs, version);
}

if (max_index(obsolete_installs) == 0)
{
  if (max_index(supported_installs))
  {
    msg = "";
    foreach install (supported_installs)
      msg = msg + " and " + install;
    msg = strstr(msg, " and ") - " and ";

    if (" and " >< msg) exit(0, "The Squid "+msg+" installs on the host are all supported.");
    else exit(0, "The Squid "+msg+" install on the host is supported.");
  }
  else exit(1, "Error processing Squid version information.");
}
