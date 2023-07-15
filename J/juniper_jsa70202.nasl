#TRUSTED 352f99acd839e7832845066dc609b9b1d5435ab264982b6f38b854a1ab9901c6a56ec5ba8cc2bfd92a12230234acc5870391618f3ef33089a9d0d2144ae46f10e810a532e66ef0664f357e84058795906d46701fee9b36b4ad5428003a8d0edc82b1aca773d7c4ea6fbd75619ce932bbd7779989081e434a22a91f5ba5b433bdfc118ae6367341459468c8a897af72d9ddbe415beb1cf0135f265993c060c0aba5bd79b3e0c66ef259bf3c4ec888bdb5c7e01b19be935151db6389fde95a4c4112ac122da33e81c70e8633f63b24ffabf84427c569e111eaf7f776b91130462fee089e887b9914b5b9d8fd555364726a2a27b45e954fe680898ac6f25ec7471b065554c099da89e3c764f6cb384b17f2ba9fcf27f294b3370d069bcff491bc7f1c0f9cff351735c2674534a7e57a851052887b66e516249c14a33f6c2d01263a414026b03da217628d1c63dcfac1cbeeae8daa4cad52b05c866838f97b7d5bd93bdd7831183b205e19c805c7423a3a2639f1db0c3197fcabd59017527b041faeb0ae4a80c3511859620dfbe9175fae5424fff21a0b9a344ad366bbdfe76761a633836a1f5872fc2ccca66502beaf961e277f791555b90e40a49d6b6049d5f02106165e43d320d924a6430f585ffcb65cee2e79b0f1dec831444ade9e3bb0ff9ea1141b81835a6d8f613a6d1a69bb6837377cf8316651eae2bba9cfd402efacb3
#TRUST-RSA-SHA256 2e3d00555379bbcb3d44c39bdc0daa28e342129e8754e5fd354c585263cb6eba94410b24b00cf577e51a905d521eeba38a10b9f7458bac87abd1b848f1d8d30f324dba583dd3311030fc0276685cab5594e387db400ae6437252c6bf9b026d30133478abd7f2daf2be27a3a11b772f4dd3befa17963e5b242d6af916a5b7887e192ff78ccec0420948bcccdf32ce6df2c9218d288fb62094960f46daaad929dc1567df8356cdbc15f2755637b17895fc1688d1411612eda27035ff1bf998e04005c64e630176887e38562dd24a94d5b9f13200cead0905b4aace5b28c0ea03d88035ae3b77ace7ee427f2029c811b00edf61b9ecfb9b8a262edf5dc30c7f46a1b55b9eb23c727bed6c6842f77e8433d114fee7e45fcd2062aaefdc4995e1cb43bf4a17c24fcc709b48ad3e1b35913a0f1f25f923bff7054e632812d4513098f72aabba7e411f36ae8ba1f3b73d1585a497a9c426c7f48a138f00ccf00ecec0ae6674e2470bd39e7098f16216ab05ed4ab8c2fc26debd1b562aaa6eedb3def016dcfa6c2a01ee3258df2a8eaf6081402bda15f9519630fd57ca54ca28efd98a12866d31d5b19730e82d33d26be9750ed6dd63281aef18f8de5844fb0e583255a96987aa70c52d88b7e18f05f6f70b4b189cc460dead8b27f3d529611a2ab5658b7f14a1c605813cdece069723d2e9b605450dd38b372d0e2f930f9d97982c50f2
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170391);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id("CVE-2023-22406");
  script_xref(name:"JSA", value:"JSA70202");
  script_xref(name:"IAVA", value:"2023-A-0041");

  script_name(english:"Juniper Junos OS Denial of Service (JSA70202)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA70202
advisory.

  - A Missing Release of Memory after Effective Lifetime vulnerability in the kernel of Juniper Networks Junos
    OS and Junos OS Evolved allows an adjacent, unauthenticated attacker to cause a Denial of Service (DoS).
    (CVE-2023-22406)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2023-01-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-A-memory-leak-which-will-ultimately-lead-to-an-rpd-crash-will-be-observed-when-a-peer-interface-flaps-continuously-in-a-Segment-Routing-scenario-CVE-2023-22406
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cdae6305");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA70202");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22406");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0', 'fixed_ver':'19.3R3-S7'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S8'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S9'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S5'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S5'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S4', 'fixed_display':'20.4R3-S4, 20.4R3-S4-EVO'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S2'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S1'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2-S1', 'fixed_display':'21.4R2-S1, 21.4R2-S1-EVO, 21.4R3, 21.4R3-EVO'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R2', 'fixed_display':'22.1R2, 22.1R2-EVO'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"protocols ospf source-packet-routing", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
