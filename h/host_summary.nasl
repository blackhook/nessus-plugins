#TRUSTED 0395852ca012b360c210e07c317da60275892f87304cb865e06c178b9af418beacd27fe9984bb6acf55dce37322534b144c47809e0fcfea1b565b0cb05c18a211a7561f0e12a2ca24da9a0405f036462e1165da48a29330fa979170d308769f5b5eb45aa221d5bb59305a22836165950d3636d24fb837e4698af33a7eaa9940e1660063804284ca993b334b9b211ae7aa7627be1f4d17a628807425305b2c48b5e4198fc292f002404adf63d5857518be35674bac003b8b5f7d5e2e17ae2d2f375ee4ff2ecb773486ffab7d351f1b8abe3a2180db3494e7c773ee5c9b9bab863d38f8e6618af9157b9b49c12564ae7433b2180231752062e232810346a4413089db9e0a5d10767b7eb519fe315411f095e27f689713fb7b25732a917310906923ddee1d6fb4b8ba6cc1a9b75d62cf9620065cf5707b40d81b52af76c8c67596c5f8e4ac9eb203011495f0f4fbb89231921f0ec4a3bbffae60b6b7cb3a10c91e525b3cbaa061962d51fde067d6715aa6e6338c238b27f79b7de1b5f9bb709bb08ccbc17d6ec884d36fb5526faed468883c3c3451f5e8da38053f1944e32e8dc615fe6866cb85591c19bc65d56093c49e74e3d377da564d25aa0d5a4337c881cb343d0cf233b6ebd28c5174af00624df725005bfbdc6211b38fdad356258cd36d57746e4742f8a0ebb363ce7de3827d6a5d767e6ce9e6a9d1708bc18f87623ab7c
#TRUST-RSA-SHA256 a413caa65de7e3ea1635e831183484c4753341e296af745d8f1745e849087cb05455460cc446c00f1ed9c34362d3cea37ce0b72d9b78670d502d67b040c536ecfb7cb876df5be63156652ee0a477b991676cd9e0a8d92414945f4866c8909a18accf24a8bea0d1bb16ba09ad2fb48dbdd99291a0d524edec74c6a75041744cc90b22e9452918b38e1bac07e70ad74b3901c3f9e73157b065b967cf527b6cfa25ce4f3af4b7fd905bda229253a944b61512102b277a9763e75cb7ddbb5680c3ca326bf838dc9ab825a2f7d0b2b0f17f68856a9493c9f7b0b2d0b81a4be55e8adb72b10a0a48b992cdcba83a12a8ba7175dd361ec57259f7f6831f3192406043a3b08b36f96adf4ee1dc696e44cd63ac4c07173351a62fbfca1ca8401f2ca796eea7d9159d91c3236b2da25f6016c1852a64b172aa5c3f9e9207c78eb1834271ac54906e752f343f7b442f0b819f46d73130f593a5aa4d8c82b1b4a9450eb205358da8b7f0376f9c06cb91a690761f707d1db683baa3536e43206050398e9541dd914412cd24737bd96d7f41701cf990e61fd432485266532b8308f8b9fadcb7bbc7c015390b93028af4d2b5a00d6fd0dc183a992020350c7370c1e3372f7b471f318e6d87e1960b0939ba8b262cd93441139273eed5f42872f67474cbbff36240c8e267975cfa9e36a9887a941283956e045f566685b27ff5b2d883c4442ac579
#
# (C) Tenable, Inc.
#

if (NASL_LEVEL < 6900) exit(0);

include("compat.inc");

if (description)
{
  script_id(96797);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/30");

  script_name(english:"Host Asset Information");
  script_summary(english:"Displays information about the scan.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus collected information about the network interfaces, installed
software, users, and user groups on the target host.");
  script_set_attribute(attribute:"description", value:
"Nessus collected information about the target host including:
  - network interfaces including IP addresses, MAC addresses, FQDNs
  - inventory of installed software
  - information about users and user groups

This data has been stored in the Nessus report database.

Note that this plugin will not produce a visible report in the Nessus
user interface.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/26");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_exclude_keys("Host/dead");

  exit(0);
}

include('agent.inc');
include('host_summary.inc');

if(get_kb_item("Host/dead") == TRUE) exit(0, "Host is offline.");

# Without this function, the plugin does nothing useful
if (!defined_func("report_tag_internal"))
  audit(AUDIT_FN_UNDEF, 'report_tag_internal');

#Double the preset memory limit for this plugin since it has a history of exceeding 80MB
if (defined_func("set_mem_limits"))
  set_mem_limits(max_alloc_size:160*1024*1024, max_program_size:160*1024*1024);

enumerate_interfaces();
enumerate_software();
enumerate_users();
enumerate_groups();
enumerate_misc();
enumerate_cpes();

enumerate_out_of_range_ports();
