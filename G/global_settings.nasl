#TRUSTED b12ee6d3c78fc05f8a8641addc76a9d48cb23e784e99a37b9c6554289db14cd06b0eaf07c2188bd7ec583aec92fdf692f11bee36e7002e74f712cd1a777cf0c749f719b213b48c9373cd8339d62ee8ee909300beaa74c834972bf5100ceecea8fe18c41e0c8ebde1daac2f995e5f384c9ec2772dfc46b5670ba7a502fcc2cf35f0ff18c4d52b31d7a22cd0ba1fae120a84c1c14693fb5c67453207ea81d5df8e4c2819c3d707c401170a8a26a5c112c3e884e974610e1c258dbbe3522a82f863637df33255e35d31ce5c45ba8e6e7b25534b101ee26b7ca389cbbf6671a8254a6e85b9a51e3007a2aeb2f381fbb6b263046c2917d628f393f49b808082d61c82ffff32883f8e92db0d9cab571e2346c77e966f9567db6f6608a76832634f9ef38c13ea8c1bf5922b45f242ca18ee388bdf1da3af18279b40bbbc7b9396cf9363f69b252bd6a40d7fcac4becfcf02532a4eb90bda5856a3a310f682fed71a97d5caa832326e8183a731be10b3aefcebd4816e8473349716dcdac3e278a0c34642f03f6933d814c64d163425be96639a92f5120e758019b8f484cdadc317f0fe542d6d4b7e426662e59f271ed0cda5062e3462cbba1591e753edd10b2bfec271233c7641dcfc3d45a6f189be61a0823d51771ba5a24ee8f299978798a68425a2eb2f1912b8f91b088d253df1b23813a15cd221f8280864f3a2d720786526f1ca78
#TRUST-RSA-SHA256 65ee20bd7eb291883cb95619922148a319d2b23b478e93b10f4d4453f4a315e8d61cccbd71507ec3ae690663a2b83a51cf520019820fe59dfd93fbadf91466b93ce84bb501c9760178b54644364b4db71045559d0575e33dc435c6198cf2f53bb42c20d4819f98f6e4b08566f7a05a37638120919ff407ffaa1aba491cfd580291075ed2036904ba33e236ffaa99449f2ffc2c7b7ee2ca40033384629200f76cf7ce11820b459a0b510ed1069bf33806a25059726df3b79a7a76a6bc080ffe109093d4058a0b497fb35291120fcbbe28133e18cf5ca98d59943275c5fef649d7cace818e5d9b05731d1e6fa01837f513861156bdfc4c75b76b6b8774ffc71c6878933b5b15b9dc5ec19cf07a62ae661a61014891a351ee5fb690daf31d215307f3353ba2df1b69ff876be2b9aa29b9b351e36545c6ded5b02fdeb8d8489775b164bee3f75394d1a0cf79dd8a3039616b6d4544af1343ee3e0265cca63e6572940796fbded7dd2146a620c4ddf5d367ede6648856ff8ccf1cbdfa30ceb725099c881edc5fa5ccda34475f8c38e279aaed94cc9648323b0be53348cda7f9b4f4ef1d678bc056c86a1985bf25b9f5aad509b3ef0d645295d7556f81ce8d1bbe1f99afa4617a2dc74154c0f650f1265fadd7abb7adb9ddd32fd0604d80562e70b4ee024a993823b7aee5b89366b86978237464565ef1965b7f27574014aa013e9236
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12288);
 script_version("1.60");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

 script_name(english:"Global variable settings");
 script_summary(english:"Global variable settings.");

 script_set_attribute(attribute:"synopsis", value:
"Sets global settings.");
 script_set_attribute(attribute:"description", value:
"This plugin configures miscellaneous global variables for Nessus
plugins. It does not perform any security checks but may disable or
change the behavior of others.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/06/29");

 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_set_attribute(attribute:"agent", value:"all");
 script_end_attributes();

 script_category(ACT_SETTINGS);

 script_copyright(english:"This script is Copyright (C) 2004-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Settings");

 if ( NASL_LEVEL >= 3200 )
   script_add_preference(name:"Probe services on every port", type:"checkbox", value:"yes");
 script_add_preference(name:"Do not log in with user accounts not specified in the policy", type:"checkbox", value:"yes");
 if ( NASL_LEVEL >= 4000 )
  script_add_preference(name:"Enable CGI scanning", type:"checkbox", value:"no");
 else
  script_add_preference(name:"Enable CGI scanning", type:"checkbox", value:"yes");

 script_add_preference(name:"Network type", type:"radio", value:"Mixed (use RFC 1918);Private LAN;Public WAN (Internet)");
 script_add_preference(name:"Enable experimental scripts", type:"checkbox", value:"no");
 script_add_preference(name:"Thorough tests (slow)", type:"checkbox", value:"no");
 script_add_preference(name:"Report verbosity", type:"radio", value:"Normal;Quiet;Verbose");
 script_add_preference(name:"Report paranoia", type:"radio", value:"Normal;Avoid false alarms;Paranoid (more false alarms)");
 script_add_preference(name:"HTTP User-Agent", type:"entry", value:"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)");
 script_add_preference(name:"SSL certificate to use : ", type:"file", value:"");
 script_add_preference(name:"SSL CA to trust : ", type:"file", value:"");
 script_add_preference(name:"SSL key to use : ", type:"file", value:"");
 script_add_preference(name:"SSL password for SSL key : ", type:"password", value:"");
 script_add_preference(name:"Enumerate all SSL ciphers", type:"checkbox", value:"yes");
 script_add_preference(name:"Enable CRL checking (connects to Internet)", type:"checkbox", value:"no");
 script_add_preference(name:"Enable plugin debugging", type:"checkbox", value:"no");
 script_add_preference(name:"Java ARchive Detection Path : ", type:"entry", value:"");

 exit(0);
}

var is_scan_sc, cert, ciph, key, ca, opt, pass, b;

if ( get_kb_item("global_settings/disable_service_discovery")  ) exit(0);
if ( script_get_preference("SSL certificate to use : ") )
 cert = script_get_preference_file_location("SSL certificate to use : ");

if ( script_get_preference("SSL CA to trust : ") )
 ca = script_get_preference_file_location("SSL CA to trust : ");

ciph = script_get_preference("Enumerate all SSL ciphers");
if ( ciph == "no" ) set_kb_item(name:"global_settings/disable_ssl_cipher_neg", value:TRUE);

if ( script_get_preference("SSL key to use : ") )
 key = script_get_preference_file_location("SSL key to use : ");

pass = script_get_preference("SSL password for SSL key : ");

if ( cert && key )
{
 if ( NASL_LEVEL >= 5000 )
 {
  mutex_lock("global_settings_convert");
  if ( get_global_kb_item("/tmp/global_settings_convert") == NULL )
  {
   if ( file_stat(cert) )
   {
    b = fread(cert);
    unlink(cert);
    fwrite(data:b, file:cert);
   }

   if ( file_stat(key) )
   {
    b = fread(key);
    unlink(key);
    fwrite(data:b, file:key);
   }

   if ( !isnull(ca) && file_stat(ca) )
   {
    b = fread(ca);
    unlink(ca);
    fwrite(data:b, file:ca);
   }
   set_global_kb_item(name:"/tmp/global_settings_convert", value:TRUE);
  }
  mutex_unlock("global_settings_convert");
 }

 set_kb_item(name:"SSL/cert", value:cert);
 set_kb_item(name:"SSL/key", value:key);
 if ( !isnull(ca) ) set_kb_item(name:"SSL/CA", value:ca);
 if ( !isnull(pass) ) set_kb_item(name:"SSL/password", value:pass);
}

opt = script_get_preference("Enable CRL checking (connects to Internet)");
if ( opt && opt == "yes" ) set_global_kb_item(name:"global_settings/enable_crl_checking", value:TRUE);

opt = script_get_preference("Enable plugin debugging");
if ( opt && opt == "yes" ) set_kb_item(name:"global_settings/enable_plugin_debugging", value:TRUE);

opt = script_get_preference("Always log SSH commands");
if ( opt && opt == "yes" ) set_kb_item(name:"global_settings/always_log_ssh_commands", value:TRUE);

opt = script_get_preference("Probe services on every port");
if ( opt && opt == "no" ) set_kb_item(name:"global_settings/disable_service_discovery", value:TRUE);

opt = script_get_preference("Do not log in with user accounts not specified in the policy");
if (! opt || opt == "yes" ) set_kb_item(name:"global_settings/supplied_logins_only", value:TRUE);

opt = script_get_preference("Enable CGI scanning");
if ( opt == "no" ) set_kb_item(name:"Settings/disable_cgi_scanning", value:TRUE);

opt = script_get_preference("Enable experimental scripts");
if (! opt || ";" >< opt ) opt = "no";
set_kb_item(name:"global_settings/experimental_scripts", value:opt);
if ( opt == "yes" ) set_kb_item(name:"Settings/ExperimentalScripts", value:TRUE);

opt = script_get_preference("Thorough tests (slow)");
if (! opt || ";" >< opt ) opt = "no";
replace_kb_item(name:"global_settings/thorough_tests", value:opt);

if ( opt == "yes" ) replace_kb_item(name:"Settings/ThoroughTests", value:TRUE);

opt = script_get_preference("Report verbosity");
if (! opt || ";" >< opt ) opt = "Normal";
set_kb_item(name:"global_settings/report_verbosity", value:opt);

opt = get_preference("sc_version");
if ( opt )
{
  set_kb_item(name:"Product/SecurityCenter", value:TRUE);
  is_scan_sc = 1;
}

opt = script_get_preference("Debug level");
# If isnull, UI is missing Debug level entirely (T.sc), default to 3.
# Still won't run without plugin debugging enabled.
if ( is_scan_sc && ! opt ) opt = "3";
if (! opt || ";" >< opt ) opt = "0";

# Don't set the debug_level KB if using nasl CLI and the KB is already set
if (! isnull(get_preference("plugins_folder")) || isnull(get_kb_item("global_settings/debug_level")))
  set_kb_item(name:"global_settings/debug_level", value:int(opt));

opt = script_get_preference("Report paranoia");
if (! opt || ";" >< opt ) opt = "Normal";
set_kb_item(name:"global_settings/report_paranoia", value:opt);
if (opt == "Paranoid (more false alarms)")
  set_kb_item(name:"Settings/ParanoidReport", value: TRUE);

opt = script_get_preference("Network type");
if (! opt || ";" >< opt ) opt = "Mixed (RFC 1918)";
set_kb_item(name:"global_settings/network_type", value:opt);

opt = script_get_preference("HTTP User-Agent");
if (! opt) opt = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)";
set_kb_item(name:"global_settings/http_user_agent", value:opt);
if ( NASL_LEVEL >= 3000 )	# http_ids_evasion.nasl is disabled
  set_kb_item(name:"http/user-agent", value: opt);

opt = get_preference("auto_accept_disclaimer");
if (! opt || ";" >< opt ) opt = "no";
set_kb_item(name:"global_settings/automatically_accept_disclaimer", value:opt);
if ( opt == "yes" ) set_kb_item(name:"Settings/automatically_accept_disclaimer", value:TRUE);

opt = script_get_preference("Host tagging");
if (! opt || ";" >< opt ) opt = "no";
var opt2 = get_preference("host_tagging");
if (! opt2 || ";" >< opt2 ) opt2 = "no";

if (opt == "yes" || opt2 == "yes") opt = "yes";
set_kb_item(name:"global_settings/host_tagging", value:opt);
if ( opt == "yes" ) set_kb_item(name:"Settings/HostTagging", value:TRUE);

opt = script_get_preference("Java ARchive Detection Path : ");
if ( opt ) set_kb_item(name:"global_settings/jar_detect_path", value:opt);

opt = get_preference("Patch Report[checkbox]:Display the superseded patches in the report");
if (! opt || ";" >< opt ) opt = "no";
set_kb_item(name:"global_settings/report_superseded_patches", value:opt);
if ( opt == "yes" ) set_kb_item(name:"Settings/report_superseded_patches", value:TRUE);
