#TRUSTED 2ca64d3fe5cf59a817afcb03f24dc48f67e4bf673969ae2754f3747d912088365fcded7926948bddc5b477a4143900d8b71bbfaae3cd6eeb9466452624fc9702664a4ef6eb0c44989c244250e4103ae8a3f12dd89a0709b06a061a70c9b8099d71949bacd3447f4ee2259b3ba16fae1819b444e7883f48194d937f4335a7974364cc333f656589dbc152c4991868d2f828fa7fe355c51a112aca0646d76862c90f0d82bae04894c6e78b82940f86b39f144fda1208702460011edf2375fd900327fc7524d99a9b1ce691f016276ad41850528d2c9346a785236a2b8c864ad7f0d8fca47b99a3267e303497b2674a9462640f291b7785fcf488da090868a46d7d5ef87d4a5cbda2b65d9a144f6e5069208ff99f6184baae273d5f8b43fc5d42bac0b8e544b48d07d4bd3dca2daac3b755e6bbb4ba7b9ae31700f8c47d403f570bb0f60618f6851ac452f26269f526a23320344ca36ec61978146675f85155b69cc3becc413c18e865c650d40dace9c8aa8ac3b361f49b72fd2eddd90d0f26fa0a72af89b04bac800ba98c4fd24d68a8fa36862a24c63c06c01489ccedbf0554013ff7dcbbd8ce16613a46d35890b12caab8c00ecd39cc029bed0916264b33ee1855319e53df77d09203e4226d186a12bf54ee4477e7e0330053cb98ce8aa8db8baafa1917069872baf92ed4cebb85c0947b14476086b0e3c44a8f9b251092e14b
#TRUST-RSA-SHA256 0a234700e4c90e34c9b1294665b7f66d9f580428b11d7a15a55da37f5fb56deeddafe4ae116097ba863bacf9efd73964da83e80eeaa853ee86ba545b63d0dab26e8f6e2e1b490d0e036855826eaba92178eeb70456c72a49efd2c094f43ab50c4f0bfb0a9668355cc761ee62e8d4c5d6634f98c23be09d7782e13e8b5538ddc9b5dd5dfe30beb5afe45f2a3044084f938160a16a64f05401ab9fa2b4c92c416a72f0fbc4240bada300bacb98c689fc42dc86930c61ef02e93d11b3604f2df428f332d4d6bcbca2707d5151e25fefb928e38483687efebb976d3db939ae0c7dc6211c8574971cc2ab639ef815e74779c67939fcd5fe8be25d240f24121bcb08c923dbddd894bda2bc26b4ebbae9e2e99a7384103595c34760da20d7de4087b6ee303a3193fc92f20bd4e2fac2ff25a15f8662fe6ee51a8d8074ed2e6d22b1b06553b4d37f04942f37fa858f7dacbec93083385f932dd96b182970d3a751dd9522f16c62daece8edcd02ad4bc1ea8460aeca72c410dba57041077b52be7cd86a307afe1d30abe7b1aecd0ac44d7fa3424eae26389a73c8b1a208ff0eff3c69a1367d981b7664863a85267d7347e92e74902dcb2bd1839263acfa72b3a6aa5f5c610a8debab1f2cd6aa9da8239c5a549d75ad83f21baec86855ef9710f7b4216755256047c6f38f26213befb1a3685f79ff670e1ad270739477435875c24a59a8bc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(83955);
 script_version("1.11");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/05");

 script_name(english:"Nessus Product Information");
 script_summary(english:"Initializes information used in Nessus product detection.");

 script_set_attribute(attribute:"synopsis", value:
"Set up information about which Nessus product is running.");
 script_set_attribute(attribute:"description", value:
"Set up Nessus product information to help facilitate some plugins to
detect what platform they are running on.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/02");

 script_set_attribute(attribute:"plugin_type", value:"summary");
 script_set_attribute(attribute:"always_run", value:TRUE);
 script_set_attribute(attribute:"agent", value:"all");
 script_end_attributes();

 script_category(ACT_INIT);

 script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Settings");

 exit(0);
}
include("global_settings.inc");
include("misc_func.inc");
include("nessusd_product_info.inc");

var report = "Nessus product is ";

# nessus environment
var env = nessusd_env();

if (!isnull(env['product']))
{
  if (env['product'] == PRODUCT_WIN_AGENT) report += 'Windows Agent.\n';
  else if (env['product'] == PRODUCT_UNIX_AGENT)
  {
    if (env['os'] == 'DARWIN')
    {
      env['product'] = PRODUCT_MAC_AGENT;
      report += 'Mac Agent.\n';
    }
    else
      report += 'Unix Agent.\n';
  }
  else if (env['product'] == PRODUCT_NESSUSD) report += 'Nessus Scanner.\n';
  else if (env['product'] == PRODUCT_NESSUSD_NSX) report += 'Nessus NSX Scanner.\n';

  else report += 'undetermined.\n';
}
else
{
  report = 'No Nessus Product information available.\n';
}

set_kb_item(name:"nessus/product", value:env['product']);
set_kb_item(name:"nessus/os", value:env['os']);

# Agent bool set
if (nessusd_is_agent()) set_kb_item(name:"nessus/product/agent", value:TRUE);

# local scan set
if (nessusd_is_local()) set_kb_item(name:"nessus/product/local", value:TRUE);

# Set feed time for UCF
var plugin_feed_info = nessusd_plugin_feed_info();
if (plugin_feed_info["PLUGIN_SET"])
  replace_kb_item(name:"PluginFeed/Version", value:plugin_feed_info["PLUGIN_SET"]);

##
# Returns whether or not the scanner machine is a Nessus Enterprise Cloud system
#
# @return 1 if the Nessus msp_scanner file exists, or the Nessus msp file exists and its MD5 is a specific string
#         else 0 (&& FALSE)
##
function is_nec()
{
  local_var separator, path;
  if (platform() == 'WINDOWS')
    separator = '\\';
  else
    separator = '/';

  path = nessus_get_dir(N_STATE_DIR) + separator + 'msp_scanner';
  if ( file_stat(path) > 0 ) return 1;

  path = nessus_get_dir(N_STATE_DIR) + separator + 'msp';
  return file_stat(path) > 0 &&  hexstr(MD5(fread(path))) == 'bcc7b34f215f46e783987c5f2e6199e5';
}

if (is_nec())
{
  replace_kb_item(name:"Host/msp_scanner", value:TRUE);
}

exit(0, report);
