#TRUSTED 4963cae55dce6ffa2ae8e8596df6d4749fcbfc8c5d84d5414d9a1ba1bbec0af0521d6c0616a0fb77ba78e774142beb44ee67adde153d9928c121a4bafe9d1189e2cb34ead3a2f9066ced1c5a067cdec0a1a6905925390a668106e4cbb5abb61440aca823475b78b4bde64c35d725bbc31bcb3a7b1a1e414d740a646ee2a9fc8e4cbf69acdc25965d774da2453cab457a39c7212adf884e00571da3acfa5f2ccb22b9b8a69d9c808771110bba14710d1180bc4093b5770adccc409cfa380c1ebd217b1569b144646434b2201942b6629a35d80c26b6e7653e75c3663cd7142edb0e1bdf6086070b71cf348814090f71422bb968202100dc06cc82dc0781266edb7453fe3077e672673ddb832de6d12cee098e9624df0b1979e684f0f5720ce5c2191e4065d2fe9489504d6a975c2960c6aa29a2257f280a3fb8b96ebca422cc0101438851ece621f39706598befff046188921865f615c595f6bc7151a15f9eff35ce13420527480ce156f9a9c00eea54839fad57e2d59feb9f3c5bd245816fe66741b1630eca7fae075319bdfdf22252faf30ef0429182e56833ea1bb8c45470eb070933c7d95823465710be4725950dd5aa8f0a2f1fdc58279831dd97aef1c889f07cf5cb3bb5cc1e4a28d6a8173edf39ae5b425be02c2769dfc184507dbd9dbb7d371bd7cf31b97131dcef9742bcd507ea1af0cf7d29dcc001bbb782100710
#TRUST-RSA-SHA256 420834c9c5f972e8935e909837f176a9aefd32a0dd381d09c7fe9ed3aedb4b928654dcafdcc8f706df0e0433cafec05a8fcb7ccdbbe60658ad382a85091efbae725e62f16886dd716b1cea1a930787c4c229e06375eeb4e9262d527b340063177b7752400dca1cba0389d995cc450b058253c03520b5e3d2a4e248e42b19edd837d64d42aeaaa3817488a16320143491678e74dd97b9f523d65478c605c8f6cf0bc20277e78c5e1defdb5da8cd16e3ffb948bd2199dca827db0c6e0984ce948e92e832f969771c64c35aef2fc200fb6a295c2526e49f082b4b4e04b95413468466bb9d158a96647261b2a18061a06cd9f92dcfa5a9481c2d3a6a15bc5f12ad116a372eb1d55237ede9c082cecc08ed4de552b98f89ae08e8ec3ea0e6350082f1717263aee119b65671e9f42dba84e16caeffecb7287ba189ca3a14cd539359eb57de84ff3d4d451b9f029f72eaa573c6380683d54d5bb8075ef34d052d40762998a0e0c29bee55cfa837eeff18a5b70e711268409cde7b046ebc3ad4cc46675840e2686bb60aafe152880e098513e60f6b3fbceea42f18a99b19ddbf88864271a14d6001e88e28c70907327627c0b8ff5eaca8ddc50c2c014405706ba4b8f8666e79ce03c04a4a5aafc7d50941645c9d568978242d86a0d34b7259897bddce88f750592cdca0fe0016b39b9213780ceb30780b89f8921c25e94b578eb43fe890
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174739);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2023-28968");
  script_xref(name:"JSA", value:"JSA70592");
  script_xref(name:"IAVA", value:"2023-A-0201");

  script_name(english:"Juniper Junos OS Vulnerability (JSA70592)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA70592
advisory.

  - An Improperly Controlled Sequential Memory Allocation vulnerability in the Juniper Networks Deep Packet
    Inspection-Decoder (JDPI-Decoder) Application Signature component of Junos OS's AppID service on SRX
    Series devices will stop the JDPI-Decoder from identifying dynamic application traffic, allowing an
    unauthenticated network-based attacker to send traffic to the target device using the JDPI-Decoder,
    designed to inspect dynamic application traffic and take action upon this traffic, to instead begin to not
    take action and to pass the traffic through. (CVE-2023-28968)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2023-04-Security-Bulletin-Junos-OS-SRX-Series-Policies-that-rely-on-JDPI-Decoder-actions-may-fail-open-CVE-2023-28968
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59d56949");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA70592");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28968");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/25");

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

var model = get_kb_item_or_exit('Host/Juniper/model');
# SRX Series
if ( 'SRX' >!< model)
  audit(AUDIT_DEVICE_NOT_VULN, model);

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'1.0',  'fixed_ver':'19.1R3-S10', 'model':'SRX'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S7', 'model':'SRX'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S8', 'model':'SRX'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S11', 'model':'SRX'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R1', 'model':'SRX'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S7', 'model':'SRX'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R1', 'model':'SRX'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S6', 'model':'SRX'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S5', 'model':'SRX'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S4', 'model':'SRX'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S3', 'model':'SRX'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S3', 'model':'SRX'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S1', 'model':'SRX'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R2-S1', 'model':'SRX', 'fixed_display':'22.2R2-S1, 22.2R3'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R1-S2', 'model':'SRX', 'fixed_display':'22.3R1-S2, 22.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
