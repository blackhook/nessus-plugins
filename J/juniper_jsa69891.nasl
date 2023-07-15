#TRUSTED 3803f7a3c988c0ba479b646db6d216832e3d3221c3073b7582cddd8666dd3caf30b263372b5f092a8e06ff26386607617770c58dcdd5d2e1713d4e7c30c67b3970af4dbb6dabe29908d90efd244bcbb8e605ca88922ef8ed14045bfcddaa2665e50c056f16a644f8741776f8463987f4de550d22fc81c64215883240786fd867460dbc2b480edd299087317e01e2d0cd4d00eaa13e087f375c9b95bf6245088d992beaae04dc2e3492315483cb9c3c3d38d46ce7ce81953c88e775e56586a5c5436054925f0e3e01bca8a9022b94f77ea41495ec49d9087efe6189d5933c13fbb96f3436a111578eb08329c4c50f71fe63c2f9038ba86afd407ee78a3bea315bd0053fff08571533b1713d52c734d5bb96c776a0661130fa4cb9b5886698c91f2a2d04368d8e245700ffc765d458b91a5a23489c9d39834044cb870ce6db146b5e12f2506f388ccacdacf504c82006f03bdc3ca32f158977bbc231a84de75ef43eee639ebbbd0e764843b78c637a28df9d57852ea1bfbbda6fa7fddc869c747320f76d6480366a441339c2e43965016da80bc2ad200be8bd5930d818e79c2ffb90d2ddffa41544dab3b11515a0d0663c8f6509d0ae4df36fe0f7a7953fb12e039b0f67d4d2dc8e8d279fd26fcac154c96a612663a677d38c67ee1ea991a03f9b63af550bee58f6b54014142e023ddc2154c3a4653d224bb88fad4d45b7fc8b7b
#TRUST-RSA-SHA256 ad879333024e2fb8af25c25c8fccb3fe08e2c792ee9ce1c436becd21ebc6121fcebf3fb53e3b49e285cf6635c0ce345bc9de13ae914f570f5aedb77410850cf7ca805758eadf637c36355a47867918565dcb82d5bb1c60431c8465afe1b728a96e3a3728611e038e0bed05eff1598e0da67c58b31a0ed915f034921d7d9cf8da99d89b017c0fa28ae8a952955601e298d8d746d233f9fabd3de10a33cb6e694b5a16a514d6e1ec9a3a1a36e66de1d04c57ccf2a1e2b87999093704d63a49923fd5a8c47a595c354e0711cda1fda2811635e80ce2720d8e0a4429c57994eda8e3fe0d627ce1ddbdb7099a6f43fae5591215ddb0b374ef4805e96c3cdbe4a1dfa343945ff78d4f65f44a4938af178d799423f445ca85bb1c6b3df45a3c9b40f44df675f4f7eeddac8a10b583005f013c57ad87e3c624d68609392bdf43aea0ab39b589a9448001c4b0518bce270f52a13e9a44d2294989e73363be6f933f4208053f238e6795b3c3e1b9ed18754b53b74ab9cd0b00c6306c57a5781db04ad4db952fc98097c2656b3ebe3633c7add9f6e6d93170fb297f15e1e2e53be8d08d4e83603ba3b70783c569f7e559d996dca4cdabe82af9aa822a349c74499e041f854fc204ec147c63b19f6d9a4ea92af9e12b9657decba381d808f3596b4dc2fae6103e294300a05a085128d53a08f34389e0325e472d74ec45c77ed9ac0c6f0186b8
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166383);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id("CVE-2022-22235");
  script_xref(name:"JSA", value:"JSA69891");

  script_name(english:"Juniper Junos OS DoS (JSA69891)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69891
advisory.

  - An Improper Check for Unusual or Exceptional Conditions vulnerability in the Packet Forwarding Engine
    (PFE) of Juniper Networks Junos OS on SRX Series allows an unauthenticated, network-based, attacker to
    cause Denial of Service (DoS). (CVE-2022-22235)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-SRX-Series-A-flowd-core-will-be-observed-when-malformed-GPRS-traffic-is-processed-CVE-2022-22235
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e7545de");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69891");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
var model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

var vuln_ranges = [
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S5'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S4'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S3'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S2'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S1'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R1-S2', 'fixed_display':'21.4R1-S2, 21.4R2'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R1-S1', 'fixed_display':'22.1R1-S1, 22.1R2'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set security gtp profile .* end-user-address-validated"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
