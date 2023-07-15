#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25252);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/18");

  script_name(english:"OS Identification : SMB");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to determine the remote operating system by connecting
to the remote SMB server.");
  script_set_attribute(attribute:"description", value:
"This plugin attempts to identify the Operating System type and version
by connecting to the remote SMB server.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2007-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"General");

  script_dependencies("smb_hotfixes.nasl", "smb_reg_service_pack.nasl");
  script_require_keys("SMB/ProductName");
  exit(0);
}


var reg_product = get_kb_item_or_exit("SMB/ProductName");

var sp;

if ('XP' >!< reg_product)
{
  var build, version, update_level;

  sp = get_kb_item("SMB/CSDVersion");
  if (!empty_or_null(sp) && "Service Pack" >< sp)
    update_level = trim(sp);

  # Newer versions use a build instead of a service pack
  # Use the service pack for older version and build for newer versions
  if (empty_or_null(sp))
  {
    build = get_one_kb_item("SMB/WindowsVersionBuild");

    if (!empty_or_null(build))
    {
      build = trim(build);
      if (build =~ '^[0-9]+$')
        update_level = 'Build ' + build;
    }
  }

  version = strcat(reg_product , ' ', update_level);

  ## prepend "Microsoft" if not already included
  if (version =~ "^Windows") version = "Microsoft " + version;
  if ("(R)" >< version) version -= "(R) "; # Messes with mappings in other plugins

  set_kb_item(name:"Host/OS/SMB_OS", value:version);
  set_kb_item(name:"Host/OS/SMB_OS/Confidence", value:100);
  set_kb_item(name:"Host/OS/SMB_OS/Type", value:"general-purpose");
  exit(0);
}
else
{
  var content, product, lang, end;

  content = get_kb_item_or_exit("SMB/ProdSpec");
  product = egrep(pattern:"^Product=", string:strstr(content, "Product="));
  lang    = egrep(pattern:"^Localization=", string:strstr(content, "Localization="));
  if (strlen(product))
  {
    product -= "Product=";
    end = strstr(product, '\n');
    product = product - end;

    lang    -= "Localization=";
    end = strstr(lang, '\n');
    lang = lang - end;

    sp = get_kb_item("SMB/CSDVersion");
    if (isnull(sp) || "Service Pack" >!< sp) sp = "";
    else sp = " " + sp ;

    if ( "English" >< lang ) lang = "English";
    else if ( "Espa" >< lang ) lang = "Spanish";
    else if ( "Fran" >< lang ) lang = "French";
    else if ( "esk" >< lang ) lang = "Czech";
    else if ( "Nederlands" >< lang ) lang = "Dutch";
    else if ( "Deutsch" >< lang ) lang = "German";
    else if ( "agyar" >< lang ) lang = "Hungarian";
    else if ( "Italiano" >< lang ) lang = "Italian";
    else if ( "Polski" >< lang ) lang = "Polish";
    else lang = NULL;

    if ( strlen(lang) > 0 ) version = "Microsoft " + product + sp + " (" + lang + ")";
    else version = "Microsoft " + product + sp;

    set_kb_item(name:"Host/OS/SMB_OS", value:version);
    set_kb_item(name:"Host/OS/SMB_OS/Confidence", value:100);
    set_kb_item(name:"Host/OS/SMB_OS/Type", value:"general-purpose");
    exit(0);
  }
  else exit(1, "The Windows prodspec.ini file does not have the expected format.");
}
