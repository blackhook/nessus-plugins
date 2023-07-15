#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59196);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/06");
  script_xref(name:"IAVA", value:"0001-A-0509");

  script_name(english:"Adobe Flash Player Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Adobe Flash
Player.");
  script_set_attribute(attribute:"description", value:
"There is at least one unsupported version of Adobe Flash Player
installed on the remote Windows host.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://www.adobe.com/ie/products/flashplayer/end-of-life.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b67dd54d");
  script_set_attribute(attribute:"solution", value:
"Remove the unsupported software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2023 Tenable Network Security, Inc.");

  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/Flash_Player/installed');

info = '';

foreach variant (make_list("Plugin", "ActiveX"))
{
  vers = get_kb_list("SMB/Flash_Player/"+variant+"/Version/*");
  files = get_kb_list("SMB/Flash_Player/"+variant+"/File/*");
  if (!isnull(vers) && !isnull(files))
  {
    foreach key (keys(vers))
    {
      ver = vers[key];
      if (ver)
      {
        iver = split(ver, sep:'.', keep:FALSE);
        for (i=0; i<max_index(iver); i++)
          iver[i] = int(iver[i]);

        num = key - ("SMB/Flash_Player/"+variant+"/Version/");
        file = files["SMB/Flash_Player/"+variant+"/File/"+num];

        info = 'The following unsupported Flash player controls were detected :';
        if (variant == "Plugin")
        {
          info += '\n  Product : Browser Plugin (for Firefox / Netscape / Opera)';
        }
        else if (variant == "ActiveX")
        {
          info += '\n  Product : ActiveX control (for Internet Explorer)';
        }

        register_unsupported_product(product_name:'Adobe Flash Player',
                                      version:ver, cpe_base:"adobe:flash_player");

        info +=
          '\n  Path               : ' + file +
          '\n  Installed version  : ' + ver +
          '\n  End of life date   : 2020-12-31' +
          '\n';
      }
    }
  }
}

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0) security_hole(port:port, extra:info);
  else security_hole(port);
}
else audit(AUDIT_NOT_INST, "An unsupported version of Adobe Flash Player");
