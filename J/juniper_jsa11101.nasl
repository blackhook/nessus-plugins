#TRUSTED 745c2528e34713082cf07b15ecf7ebefd4a06a4035c76ce3c1b6b67e44fb54eeadedf1292c67f8ffd21a3e87e81a6fd8bb70088a3c5ac2fb326ebebb92bd9b06297b5dfdab44a468163d6b97882213dee84a18c925302b049b760d9ce0c7bd60ea7437a6b318a9994752814e47c80dafcfd005d6592f67df01524c4fe47ef6b4e137bb88e85ce010e3ab9645ac698fc2953b41e06f284a1db49cc6c9e78f5774f3d7802b951c200fa74b2dd68aa27d9db82d7ecc6e7d6028694bdbc0ef2b3a3e10e1feeca56e62248e0a43963a160adf21d98ba44e1dcb2f745ead2c8dfa548cda1c1205e149ad4b793e56b71ebc0a74129ff857f06ec8aa744a5aa5ce01c05422986754f14c054fbccb9b74d174f958355bbaa1dc4c8bc567d44c8f44e9aa013159c0faf0f34850cc47cbebd04229b474bcdcd9073fed745e73872dd8aa58fa4a5aef001c11e3b76d20b81031d5e96938924d186b5e04484e38a0ba909f155f490f25404700d922aa4ff0238e7010a5184eb448da672a05310f184fb37fbd6995e52626e5dd78173d2781e96841ffc2724f7b21afd56d61a06db047cf048934cf2bf0f4d3c92ce524a4e9732f7078e06520641259996bee770f95b19c8ebd1d6194df160eb8e24f7d83487fac344e7082df4a4c97f1b20ffc97c83b723996b6f60796e9e2ebb48c4995ec7a8b2701725dffc86f23daa9385263caa6c8ee6195
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146090);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2021-0211");
  script_xref(name:"JSA", value:"JSA11101");
  script_xref(name:"IAVA", value:"2021-A-0036-S");

  script_name(english:"Juniper Junos OS DoS (JSA11101)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability. An 
unauthenticated remote attacker can send a valid BGP FlowSpec message thereby causing an unexpected change
in the route advertisements within the BGP FlowSpec domain leading to disruptions in network traffic causing
a Denial of Service (DoS) condition as referenced in the JSA11101 advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11101");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11101");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0211");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

vuln_ranges = [
  {'min_ver':'1.0',	'fixed_ver':'15.1X49-D240', 'model':"^SRX"},
  {'min_ver':'1.0',	'fixed_ver':'15.1R7-S8', 'model':"^EX"},
  {'min_ver':'1.0',	'fixed_ver':'17.3R3-S10', 'model':"^(?!(SRX|EX)).*"},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S12'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S4'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S12'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2-S8'},
  {'min_ver':'18.2R3', 'fixed_ver':'18.2R3-S6'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S8'},
  {'min_ver':'18.4R2', 'fixed_ver':'18.4R2-S6'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S6'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S6'},
  {'min_ver':'19.1R2', 'fixed_ver':'19.1R2-S2'},
  {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S3'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S1'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S5'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S1'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S3'},
  {'min_ver':'19.4R2', 'fixed_ver':'19.4R2-S3', 'fixed_display':'19.4R2-S3, 19.4R3'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R1-S3', 'fixed_display':'20.2R1-S3, 20.2R2'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R1-S1', 'fixed_display':'20.3R1-S1, 20.3R2'}
];

override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:".*protocols\s+bgp\s+family\s+inet\s+flow", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
