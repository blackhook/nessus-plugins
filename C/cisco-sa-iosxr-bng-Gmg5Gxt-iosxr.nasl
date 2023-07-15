#TRUSTED 339ddaa20ea8727b13d8308da3b7d89629354ae330ac723c54dac8a89551baa7e8c28dd41c8a8e970423802bb2247ecab434565bd78a85f0ccfb239dd05e95b36742dbd0b462382dc0951cdba88c538f8c5b123e100e5115ba83c98bcc34c67b594e1e5b6db8155b5b3195326012ccb670574ae6dedac56630c929a5b66e01d75db68957725baf1ef49d8fa2a41336b763379ce805b76c5b1ab7834abe683b8bc9b761b04438e202170683ebaeb9e2056e79a306e9db8d8b56ecde6c33e3d9240a75be370885eae493a1ce380736c9f16f8895b479787e29bfc551d9068ac7aaecb4e40043400ee9bc0b78b94a378faf466e25d4b701a8ad470f398b519f3a8e499032e3fc831770d629a140317faa8c08624d13f3cedfcc30c94faa084b300e09f1118833d3e2448b35ea7b21451541a4caf1e8e649103cd2c84dbd6994b99dc8417561706c55ac36e642ca48f55b21bb41beae3f4a647b261fb714a91df945462d5bdc6a85219819730479c2705a5fb543410bb2e115ccf81b36b7d1ca4ec38f009cba9e0a96467640e9f504117799da5ac8e14acc038f138efae7c39bee1d39a556642a733919e15e69c03a199f684a4c8542620460259b49b197b4108cf6283ace2cc6ac20809b7ed14617335b9ffa7ac9f6fe54666dc290c6525664433d83651225407b00575d6b858549b00482f6d7c603fc56bbd65960b65622b8b94e
#TRUST-RSA-SHA256 0a0b1daf335df1e121f071c163c805f72624c311701d57a1e8189c79b9596cdf695e34726d50b810b6bfb284b69f6be059f706a20949ee0e8b5f75f26e0069f6ed68ac4972b3abbd2971bc97891adcc26b402c8fbc0dbc2226302e651880e80f3bbcacc298641b0d977b48e20d343a7c1683a26b8468e6442b187a3eaf6728d3ad938af9a88c1bbdb2f946ada1d9e044b288c1a4ae1db589dbd11fd3594c8ed7cec08e9538a4d5afa2c254bbc1ca8a9ada2c352031f7665a087802ad17f7dded05662af762b2f53f826ba555bce6408840c5da7c69ff8ae73da279318beb56f9b303b85258d2b1770ee848ee66539aecda34a55514bc731dc3d859e82d64efb3a0b47e10e1bfd54ec3ff757bea507c085c2a4e1d3de74fee222d3775ca0b69210a6309276b891a28ebb6e6c062b482f6518b5dbc0110da2db4eae7c60c76abebda3d097c438b5dfe031227686d48bf55156c3942d7ae41f41146f681f053c92f25b9b8ac0a2493c5d6fbe20a80ef9d66b0ea4a04f55960fd6d09a435d8a362bd19139ea10a9fe18e842eaf950c30a1e088c688ada412c1d394f6f6bac554dc8966cfb0fb93f2d9be671d82d811600dab8b55e0406aa739a57f85531eaba86572165c899943f1c0ee1220de97942a25d002fa41fdfa98ccfc5191136630844aab96437404934215e2e7e50ecbe9da85f7ef60825ea2568aff5226dffb5097f7ad
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165215);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-20849");
  script_xref(name:"IAVA", value:"2022-A-0380");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa57311");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-bng-Gmg5Gxt");

  script_name(english:"Cisco IOS XR Software Broadband Network Gateway PPP over Ethernet DoS (cisco-sa-iosxr-bng-Gmg5Gxt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in IOS XR Software due to the PPPoE feature not properly handling an
error condition within a specific crafted packet sequence. An unauthenticated, adjacent  attacker can exploit this
issue, via a sequence of specific PPPoE packets from controlled customer premises equipment (CPE), to cause the
process to continuously restart.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-bng-Gmg5Gxt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e145bee");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74840");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa57311");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa57311");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20849");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(391);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl","cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');
var smus = {};

var model = toupper(product_info.model);

if ('ASR9K' >< model)
{
    smus['6.7.3'] = 'CSCwa57311';
    smus['7.3.2'] = 'CSCwa57311';
    smus['7.4.2'] = 'CSCwa57311';
}

var vuln_ranges = [
 {'min_ver': '0.0', 'fix_ver': '7.5.2'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
var workaround_params = {'pat' : "pppoe padr session-unique relay-session-id($|\r\n)"};

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwa57311'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  smus:smus,
  vuln_ranges:vuln_ranges
);
