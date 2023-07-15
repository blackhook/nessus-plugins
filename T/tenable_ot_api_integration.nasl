#TRUSTED 6bbf6e68cc38b1b8dc47b48f3576c903f1ed027dabdeb6dccea72ddb1e6b86cb784c8f4fae042f5649035a297b7c10a204b5406707895e1e06993d2a85b12d329b17aef19a3367886b28453eb2fb1cacf2998dc316ad25f7aafa9e0e48bc2c52e756c7beec5bd873654dd02b60d5677613b40c8434428fa4e39971a339c97685815150b4675437d991bed9f0778bcfbcd5b9d3d9b075a050b2058433b86055ecfa6f996ee5b106d7b93dc5594ebd3ec5f1b1602593b81152ff920d5591e8f55d388289dc286b43ee862b35c88041a405ac84ceb780ea8d9bb91237de762f4fb43167acf958535cef9a6d68a3e67c81de5e162940f3f2d30349b1e151c27a39fafc47af1da3dcc8a2a768725d5d98e2e2513f8f7db49bf959284d5884438f48267bceb6d170a6c536ba093ff252267416b4ba31d022f94ff55089295e13c4163ddcc44e65eb1f2a1176e84224239a77f3f8bf36fe9fe627383e1dfa6d275973f9d8c44f4c11aa927e0bec0e3f4ecdfcc69c93713030694f75e43cd4e6432af881a29d324d8de70a0e89a8edbcc58fc1e3ac5c6db0853c6299533c99cd53ea9c8664b955cb58e91a75346357fe2ff47083b305e8951c2c4400e99a7ad53fe28cd74fbe565058d0f5a97a9cb98d91c1145629f732c0838bf64c3f839924726fcfcc767bf0624cefad50194443061f9c803677cbe50034a5b57677389fbbd7d1491a
#TRUST-RSA-SHA256 99942424596356a9eb6107c98aae85ec692832f79bd9f5d5dadcb9fe01b725fad64d96bb44dc84f74c7c59a3956559ff4b47242827b1fd3a2c16f540b6ba12f09e565cc2a228a8104f05b5c1323d5e66c348d4dc7da3583db3788436ce9dd6c5c654fca3d292cd8786046e4276602a9b1563cc8faa9182751a4e9e52df30f96f7c43a226478f7645173b89f879837b9a3630eb9594d3482c24a9b4fc41fafe43ba33cfc0b9d71d3803fa32f1809437bdad7f2f2d742e01e3feb80960333def0bd3f3f27acc42aac580d352920a9a6456dcbc6f715bd3db0c253a375adab60c6394c0b463af77184c0f3c2d7de6c3ee6ce2da2cd5a57a36bf291cceaeb8e1db8bcc3977e805c9b9ddf51bd45a9fa8203afba09dcaf669f37f5aead2702d4ea497088a74a344c0c0dcfe5ef1399875edf24f1a47058d23e587f9f0fd64df7539fe285876ae171f6dc0317de2b734273eacf25dc186dcccfc3ba2c5ea6a10216783ef04154d0877d7b0927971b4968c6a1ac164ca4bccf3d10424ab1db3a8b3b0810c543d2ed4a915ff311eb64f3d92c906961e4bcaec3eb143be0439f3fd933b55d215a853409bb8f273b799b272507fd07e8e93b2e0c9004bd087dc81e3748f30dcb9ac7b671573b572e263051c7ff8a1ccd8772464b8a4373f46d8cd83c34d1e9df952fd0237cbe24c69cc0537ca4ab6581d36ec27a91f4c39beacbd458e44fe
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(500000);
 script_version("1.6");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/21");
 
 script_name(english:"Tenable.ot Asset Information");

 script_set_attribute(attribute:"synopsis", value:
"Integrates Tenable.ot into Nessus.");
 script_set_attribute(attribute:"description", value:
"Integrates Tenable.ot into Nessus via the API.

This plugin only works with Tenable.ot. 
Please visit https://www.tenable.com/products/tenable-ot for more information.");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/07");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Tenable.ot");

 script_timeout(600);

 exit(0);
}

include('json.inc');
include('spad_log_func.inc');
include('tenable_ot_assets_funcs.inc');
include("base64.inc");

#Double the preset memory limit for this plugin since it has a history of exceeding 80MB
if (defined_func("set_mem_limits"))
  set_mem_limits(max_alloc_size:160*1024*1024, max_program_size:160*1024*1024);

var api_data = get_kb_item('flatline/tenable_ot_asset_data');
if(empty_or_null(api_data))
  api_data = get_preference("tenable_ot_asset_data");

if(empty_or_null(api_data))
  exit(0, "No OT asset data found.");

if(api_data == '{}')
  exit(0,"OT asset data is empty");

#replace_kb_item(name:"global_settings/enable_plugin_debugging", value:TRUE);
var json = deserialize(api_data);

# Error handling
if (empty_or_null(json) || typeof(json) != 'array')
  exit(1, "Failed to parse the JSON.");

# Generic KB item for detection plugins
replace_kb_item(name:'Tenable.ot', value:TRUE);

# Process each assets and set KB items
var assets = {};
var all_keys = {};

foreach (var asset in json)
{
  #spad_log(message:'Processing asset data:' + obj_rep(asset));
  # Error handling
  if (empty_or_null(asset.vendor) || empty_or_null(asset.id))
  {
    spad_log(message:'Missing "vendor" or "id" key.');
    continue;
  } else {
    asset.vendor = str_replace(string:asset.vendor, find:' ', replace:'');
  }

  # Set KB items and store asset data
  var kb_base = strcat('Tenable.ot/', asset.vendor, '/', asset.id, '/');

  foreach key (keys(asset))
  {
    # This element is large and not currently used
    if (key == 'protocolUsages') continue;
    all_keys[key] = true;

    if (isnull(asset[key]))
      asset[key] = 'null';

    else if (typeof(asset[key]) == 'array')
      asset[key] = serialize(asset[key]);
    
    if (key == 'assetBag')
      asset[key] = base64encode(str: asset.assetBag);

    assets[asset.id][key] = asset[key];

    replace_kb_item(name:kb_base + key, value:asset[key]);

    if (!empty_or_null(object: asset.assetBag))
      replace_kb_item(name: 'Tenable.ot/assetBag', value: base64encode(str: asset.assetBag));
  }
}

all_keys = keys(all_keys);

# Populate scratchpad table
tenable_ot::assets::create_table(asset_keys:all_keys);

foreach (var asset_data in assets)
{
  tenable_ot::assets::populate_table(asset_data:asset_data);

  # Generic KB item for downstream plugins
  var kb_base = 'Tenable.ot/' + asset_data.vendor;
  replace_kb_item(name:kb_base, value:TRUE);

  # Uncomment for debugging - see RES-71639 for more info
  #tenable_ot::assets::report(asset:asset_data);
}

# Exit without reporting
exit(0);
