#TRUSTED 420a1ae907a58a548a3ad153d63ea088a3ddd1f6592bcc206cbaea3e4e97a1be6cbbb51a83e82cd5c499bee401999f3ea877c540c1447dcf9710bcbcc62da7169b6477b519e35a9a9eff776091e9c26f4e022f0437fbcdfcf6eecc0c86a36bf8ccac00cb7a6bf7f13265c676256c6e1484fde5527920b1d17e4747cfa041a2d76992627dc33fd3a2f889163b2e5445f633d58d12492ae220fa7763cebfaeef1e75d5b884d18bfc13ccd39b61844503331eec0cc98771bff6ba1631f8b0dc9d28ba671f1ea1eafd5aeeec386830bb309b552cd64040cb35f702387691f53cfb9111172186cdca6d1077633fb2b86d479d97ffdfcc58bda1d77753850055e14608c145b5a54cff775dd9badec3c3fe6efbce712d92928884a8adf3725b2d8db421f8808c12d7b78585085b0d4abe080df9d8160723cf090fbbfa5d9021956338b4a232b45bef490fa091e052105a6e17e6d997fb1178966457efb520c410ff2609baa8b08daf0ac92bad532f62650a55b12a1025c395734918b7c34e3a387d9fe99dd4eb53537456bed66c56c00a430dd8ffa7faedc39b6e592c0701c599f5fb75e0048d84653bd1d937309f94314918163e46d6bbf6e981274d69a2ce12e14aade320e260bda5c90e1ce986c9bbe275fc3070d3a18671826657eb752395b2e7a8191a1425bc488fb171e1beaf94c7fcd0ed622ed46bcac5ec0dec0066018f3000
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143381);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-1670");
  script_xref(name:"JSA", value:"JSA11067");
  script_xref(name:"IAVA", value:"2020-A-0467-S");

  script_name(english:"Juniper Junos EX4300 Series DoS (JSA11067)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote  host is affected by a vulnerability as referenced in the JSA11067
advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11067");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11067");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1670");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

if (model =~ "^EX4300")
{
  vuln_ranges = [
    {'min_ver':'17.3',   'fixed_ver':'17.3R3-S9'},
    {'min_ver':'17.4',   'fixed_ver':'17.4R2-S11'},
    {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S2'},
    {'min_ver':'18.1',   'fixed_ver':'18.1R3-S10'},
    {'min_ver':'18.2',   'fixed_ver':'18.2R3-S4'},
    {'min_ver':'18.3',   'fixed_ver':'18.3R2-S4'},
    {'min_ver':'18.3R3', 'fixed_ver':'18.3R3-S2'},
    {'min_ver':'18.4',   'fixed_ver':'18.4R2-S4'},
    {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S2'},
    {'min_ver':'19.1',   'fixed_ver':'19.1R2-S2'},
    {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S1'},
    {'min_ver':'19.2',   'fixed_ver':'19.2R1-S5'},
    {'min_ver':'19.2R2', 'fixed_ver':'19.2R2-S1', 'fixed_display':'19.2R2-S1, 19.2R3'},
    {'min_ver':'19.3',   'fixed_ver':'19.3R2-S4', 'fixed_display':'19.3R2-S4, 19.3R3'},
    {'min_ver':'19.4',   'fixed_ver':'19.4R1-S3', 'fixed_display':'19.4R1-S3, 19.4R2'},
    {'min_ver':'20.1',   'fixed_ver':'20.1R1-S3', 'fixed_display':'20.1R1-S3, 20.1R2'}
  ];
}
else 
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

override = TRUE;
# https://www.juniper.net/documentation/en_US/junos/topics/reference/command-summary/show-interfaces-irb-l2.html
buf = junos_command_kb_item(cmd:'show interfaces irb terse');
if (buf)
  {
    override = FALSE;
    if (!junos_check_config(buf:tolower(buf), pattern:".*irb.*up"))
      audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
  }

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);

