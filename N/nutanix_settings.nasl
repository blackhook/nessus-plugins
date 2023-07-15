#TRUSTED 64a03dae1828e73ffd4762acaa06659f948746f725c3c1840ee3feb95ab8e2a0abfb1093fc2c56e7f0e043e970a30e71a72296d8963c9cbea40a7d2409c69571559925e4475a78a2f13a63fc7e7fd62a63d3aa2e458496b7b90a4f198a25aca4a5fc85ebfae9c1a4e3e58a1610f60f55b3a3ac01c657b5ea537b44d1f24e64c78110d4e3b02191f3f6fc6e7849fb33e759fdde4ccefce5c309f3bf38f9ba81c1ca1dd6af17c5869ae1c2f102aa40bfe8aa251f56bcece489debaafea8b4dfe2f7edcf7a59b95a2b501106f210d88b4908766c84a3c259bda4888c38fd22646b3bd7e772ea84e5869caba463597e5b4729ce215e842f59002107468b4aea1daed55217f6f7f1fabf13ba4a0ab1f13f217e30dca91513ed43e4331aadc5e4e474710edaba1937c23b5386d369de7d623fc68c69a4a77d6172dd7db04456b046415005e4a7cccf29cdbffa3afb81bddc29227945cf4961ba69487463bf2a5a377a1b2eeb713a7caa22d15f47ce7c26c0e5d07ce097a28deee9f703676e615c3ae12b53f1e9c0678d34a5e37a5280e0ceedfdb1f4199b3d46752322acab9342e98a2276e9de52107ab667072f21f0830b845ba311cbc511b09612ab6eb18bb631b88619c1b421753d431a222a8421147103508c7db6be917f081b9f152b1be29105b4ad58d25b12cea53a2d38144d7e8d21381eb77ab1ef3812c42b3bac2fb9cd951
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(160184);
  script_version("1.2");
  
  script_name(english:"Nutanix Settings");
  script_summary(english:"Set Nutantix Integration authentication settings to perform authenticated security checks");

  script_set_attribute(attribute:"synopsis", value:"This plugin configures the Nutanix Integration.");
  script_set_attribute(attribute:"description", value:"This plugin configures the Nutanix Integration.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:nutanix:pc");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/25");
  script_set_attribute(attribute:"plugin_type", value:"settings");
  script_end_attributes();

  script_family(english:"Settings");
  script_category(ACT_SETTINGS);
  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_add_preference(name:"Nutanix host : ", type:"entry", value:"");
  script_add_preference(name:"Nutanix port : ", type:"entry", value:"9440");
  script_add_preference(name:"Nutanix username : ", type:"entry", value:"");
  script_add_preference(name:"Nutanix password : ", type:"password", value:"");
  script_add_preference(name:"SSL : ", type:"checkbox", value:"yes");
  script_add_preference(name:"Verify SSL Certificate : ", type:"checkbox", value:"no");
  
  script_add_preference(name:"Auto Discover Managed Nutanix Hosts : ", type:"checkbox", value:"yes");
  script_add_preference(name:"Auto Discover Managed Virtual Machines : ", type:"checkbox", value:"yes");

  exit(0);
}

include("nutanix.inc");

var host = script_get_preference("Nutanix host : ");
var port = script_get_preference("Nutanix port : ");

var username = script_get_preference("Nutanix username : ");
var password = script_get_preference("Nutanix password : ");

var ssl = script_get_preference("SSL : ");
var verify = script_get_preference("Verify SSL Certificate : ");

var auto_discovery_hosts = script_get_preference("Auto Discover Managed Nutanix Hosts : ");
var auto_discovery_vms = script_get_preference("Auto Discover Managed Nutanix Virtual Machines : ");

if (!host && !port && !username && !password && !ssl && !verify)
{
    exit(0, "Nutanix settings are not configured.");
}
else if (!host || !port || !username || !password || !ssl || !verify)
{
    exit(0, "One or more Nutanix settings are not configured.");
}

set_kb_item(name:"Host/Nutanix/config/host", value:host);
set_kb_item(name:"Host/Nutanix/config/port", value:port);
set_kb_item(name:"Secret/Nutanix/config/username", value:username);
set_kb_item(name:"Secret/Nutanix/config/password", value:password);

if (ssl && "yes" >< ssl)
{
    set_kb_item(name:"Host/Nutanix/config/ssl", value:TRUE);
}
else
{
    set_kb_item(name:"Host/Nutanix/config/ssl", value:FALSE);
}

if (verify && "yes" >< verify)
{
    set_kb_item(name:"Host/Nutanix/config/ssl_verify", value:TRUE);
}
else
{
    set_kb_item(name:"Host/Nutanix/config/ssl_verify", value:FALSE);
}

if (auto_discovery_hosts && "yes" >< auto_discovery_hosts)
{
    set_kb_item(name:"Host/Nutanix/config/auto_discovery_hosts", value:TRUE);
}
else
{
    set_kb_item(name:"Host/Nutanix/config/auto_discovery_hosts", value:FALSE);
}

if (auto_discovery_vms && "yes" >< auto_discovery_vms)
{
    set_kb_item(name:"Host/Nutanix/config/auto_discovery_vms", value:TRUE);
}
else
{
    set_kb_item(name:"Host/Nutanix/config/auto_discovery_vms", value:FALSE);
}
