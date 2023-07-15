#TRUSTED 39d8668b152d406a05b97b7b149b46261351f821caba30b4e8fc0ec622eb04627dc3508dc6626d2e89971940e34678a3d17f31867555a3c2fa71484b5c250eb61fe18dddbfdfa9198ba859c308fceb5cfb0958d732f30c22cf1861bb2e1cb9642ce1ff51d6457a69295a426f59fdad12f1ea00d20a8939817b1a6597b02c337944b3f6274bf84ee0953cf3a79bea23f7f57488fa83a8d429befda2e75ed807825af4f03a7aa45f041f780d3e26f0b8c6b220e27cde8318784d42f075b68ddfe875461d2ec6a17f346f80fdefed509d8230001acc0cfcd8bca06e0d7e2595301685c09da4e3adbd0d1cb27fc158aa3743abae46a3cded4eb60f0937dd3eb46a274342b36e116b66272ffe07121b60c00b1bb1e2b9f35d67ae039296da3866de02ceb8d332f283f29c87033f7c26cd9539649383946664442d8feb1df1635a71158a328fb73a2164ae55c6c6caf84efc183a08dd0da89e43f7b063aaa5e5088341091ba371f666e764b76c4c3fa83680ce3d221e09406b1c6b6eac41f95204069c5f04e4fc62e036d6f6bf6be207ab2dbd871f17d2ad00de8a5d612579bc74b0c152d0d4a269579e411dfeed6b5813224865d77847b7f4b4d61d525feb87475d42909057d62c28ecf26896806e3c06f92b383cd31e0742a1eb7534f283bc374c34c6876b391cf9c74de71076ed91caed6fda065cfcece0c7b37597e980e6f08991
#TRUST-RSA-SHA256 0943fad68c6fbe0d2ef59d8302edc5da560384a7c4a7afd92af27da3244b189b447914482f1c025651004d8c38ea06827e7466546539c0666a1082f0f553d20e850fe3edaa1fad19dea7d5fcc89be54bf687475d6dacb5f77c6ba924cd9b55609633ef084e526a70da8e8fb32f45c5ef7d71344d1aa9a47606b45abe99137e65298b77e74d478d04d141462c94f2613279a5de62fa659b5e036af67ecfcdb5e5f43fd71895fa6124436956d8a76145f71e695c4a59947d9e2b4b96506a42bed66b6dd3ff500e1143f0bea836d1a04a3330336d4cf424b995e8caccba11ded78ee1c74d565e43a51c78601ad16426004f0ee307128430ee095e61d639f59e7670ba22be66c4b546b3f6667ce2b2f54ab136bf8a29d434eeeb64368d11e26782ee58680dcf502c50c65e671f9f207bb27f28106e620baa9f00bc25135df3d9097f56ec09642e638ae1764c1109743f7205762efeb10de38d4109e72dfb4755aab7adf48bbf51688794ad40e4b717dce8811464c5df207e9a43803237559d03c6642fe873ff5c7f293dab3f136be29a302efc57cc924bc5fd66e051fff7cf4c9eef5941e07adc25b96ddd767dcf77a04b6566969ae6bed6eff5981580fa9082cc427daade1fcc1b6ba789ed125b6189b90a5a13abbb38697859f75c20e18e90ebcde5d618775fadaabdd4b68726b3f04573c4268cbe50949ce45f9770fb90a0eaa7
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172047);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id("CVE-2023-22399");
  script_xref(name:"JSA", value:"JSA70195");
  script_xref(name:"IAVA", value:"2023-A-0041");

  script_name(english:"Juniper Junos OS DoS (JSA70195)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA70195
advisory.

  - When sFlow is enabled and it monitors a packet forwarded via ECMP, a buffer management vulnerability in
    the dcpfe process of Juniper Networks Junos OS on QFX10K Series systems allows an attacker to cause the
    Packet Forwarding Engine (PFE) to crash and restart by sending specific genuine packets to the device,
    resulting in a Denial of Service (DoS) condition. The dcpfe process tries to copy more data into a smaller
    buffer, which overflows and corrupts the buffer, causing a crash of the dcpfe process. Continued receipt
    and processing of these packets will create a sustained Denial of Service (DoS) condition. This issue
    affects Juniper Networks Junos OS on QFX10K Series: All versions prior to 19.4R3-S9; 20.2 versions prior
    to 20.2R3-S6; 20.3 versions prior to 20.3R3-S6; 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to
    21.1R3-S4; 21.2 versions prior to 21.2R3-S3; 21.3 versions prior to 21.3R3-S2; 21.4 versions prior to
    21.4R2-S2, 21.4R3; 22.1 versions prior to 22.1R2; 22.2 versions prior to 22.2R1-S2, 22.2R2.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA70195");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA70195");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22399");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^QFX1")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'', 'fixed_ver':'19.4R3-S9'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S6'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S6'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S5'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S4'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S3'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S2'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2-S2', 'fixed_display':'21.4R2-S2, 21.4R3'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R2'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R1-S2', 'fixed_display':'22.2R1-S2, 22.2R2, 22.3R1'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"(set protocols sflow collector|set sflow interfaces)", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
