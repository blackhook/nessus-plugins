#TRUSTED 327b9974ec56700f8acd2a57a3c9ba2a047ad8a4f42312dd7ab8f73c960688ee00caa6d342901c27dc5f94cf7dd0abe8e7ec2d9448aefe1f6407729d67f36c66928bbe964cd3ee1051facd5545b3099103be885243554458e13176e33d2f070efaa441c407f77021ff2220c2edd2dfde3b16a28f4f33c97308bb6c9bce24a7d87fe5814f70e95a74fa4166a0229a6f265add66a7927a890518bcad7e529bbfe79c0690a2dbb2578c2e7968992109df1742c6196a3340410e2b4d4444e94ae54a2392cfed698dde21fe9455c33ea9502ff522aaa6659611565ec807fc96a8318d8901b20b23747fc6a44582cec2e6296caa8e55ef9071f5dfee940fce777b019415fab06bb96d283146e7d1ef5c207957c744a053f6c4326a6faa3c7ee8a086aaec96003b20adccccbad79d66feb334961586dcfe5fc1156b5759fa75668889d65ee9d478808b0da655d914e02b451ba8c45939ae175a7cc429ace378df5e321e2c6c96463290ce72101708e9098920277dc03daa2643f659fcb694979fe2554ee44bb89f731604e7a2329961784ffdbcac64e6f0f3f2f8fbb03d76954420d548e17df49cb203b528fe4425f7d603876a2e4532353f58a38defe7d9aa1434f0d86a4c6ff1f2a5c5eac7cb80106943bf7ad34437a2107597f5eb5ebfb2242fac093bc0798e0f8c9dcf6358c44415a1537193756081749d75d4cd4ad0bf9dd206fb
#TRUST-RSA-SHA256 996a916b2373e2dad1f5d1e85772eea4fd2581e52a8a866a17657a5af86004d45d208519e2bf4c29338801b19d921fe00f15030ce8ef78437197914c195a9eedfdd20d4ebbe620bada39a7ff4d7b0ebf7b0fed95ee1b5dcbadddc79b4d17408e766ffe121df87b213e317fefe4d4a8462acb27c389ba7c55bcc3adcaf8e326e0171d43159602df5775da2bbd52be690669a50459fafb34185d60282456a170489ab5bb44275414631765d92880882c75267797ff6270b90a226485a1705b07ec39cd34a747bd394ffc8eeb1d79e2d6b8bac8fba41bdd04b53a27e120b113916f488d1f22f5191d078e2fe29b00b1f7744b2245d53dd8e097c9b535251ef677c4b1f70df943bac0ce4f8e2a2ca341e29cf41283d22fc434348e941d18e401003489f4acd5b8ab1b14e2855ad0b6382199e7d30491cdc25de75dd9777a92c66b9aff0e124936430c0a2005e1d479b0281c426fbd51c8cccb0d2adf4c7bb8fed446aff3630e8c9f4b1671afa4dbb51c77757cae11cb0d706c1bd74891eb4d2cac53502b7d7ca6d926de1f9f84a7defc0f8bb655cdd8f8e06376cb117f1278d617ba9be6eb7ea9e6876797827bb570f413c143df20dfcd9588277f6615a7658ab81d7d251a465b2b6f8a9bb3be044d36fa33af1d312e9f0b4ad22bb5482a75bf5c3fd9902aa8442c7f92014faba2825c72b4b2fed541d42088552a8ef86f4a5f4ece
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166332);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/02");

  script_cve_id("CVE-2022-22199");
  script_xref(name:"JSA", value:"JSA69898");
  script_xref(name:"IAVA", value:"2022-A-0421");

  script_name(english:"Juniper Junos OS DoS (JSA69898)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a DoS vulnerability as referenced in the JSA69898
advisory due to the Improper Handling of an Unexpected Data Type in the processing of EVPN routes on Juniper Networks
Junos OS and Junos OS Evolved. An attacker in direct control of a BGP client connected to a route reflector, or via a
machine in the middle (MITM) attack, can send a specific EVPN route contained within a BGP Update, triggering a routing
protocol daemon (RPD) crash, leading to a Denial of Service (DoS) condition. Continued receipt and processing of these
specific EVPN routes could create a sustained Denial of Service (DoS) condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://www.juniper.net/documentation/us/en/software/junos/evpn-vxlan/topics/ref/statement/evpn-edit-routing-instances-protocols.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8dfd1b7b");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-RPD-core-upon-receipt-of-a-specific-EVPN-route-by-a-BGP-route-reflector-in-an-EVPN-environment-CVE-2022-22199
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63c352a3");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69898");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22199");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges;
if (ver =~ 'EVO$')
{
  vuln_ranges = [
    {'min_ver':'21.3R1', 'fixed_ver':'21.4R3-EVO'},
    {'min_ver':'22.1', 'fixed_ver':'22.1R1-S2-EVO', 'fixed_display':'22.1R1-S2-EVO, 22.1R3'},
    {'min_ver':'22.2', 'fixed_ver':'22.2R2-EVO', 'fixed_display':'22.2R2-EVO'},
  ];
}
else
{
  vuln_ranges = [
    {'min_ver':'21.3R1', 'fixed_ver':'21.3R3-S2'},
    {'min_ver':'21.4', 'fixed_ver':'21.4R2-S2', 'fixed_display':'21.4R2-S2, 21.4R3'},
    {'min_ver':'22.1', 'fixed_ver':'22.1R1-S2', 'fixed_display':'22.1R1-S2, 22.1R3'},
    {'min_ver':'22.2', 'fixed_ver':'22.2R2'},
  ];
}

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"protocols evpn", multiline:TRUE)
  || !preg(string:buf, pattern:"leave-sync-route-oldstyle", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'running a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
