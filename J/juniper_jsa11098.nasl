#TRUSTED 8ad2af5cbe5ad5523e3789ebb0ee4e8b283091371b6a8c664782689117cc6dd060633776b7172d1e59331d991fefe04dd365325285d553e778f9bdbc6cb37081e13f5eba47f20eae0865fbcc6fc9c2a4faad4b7705e1ee1beaec4ca9082f91eb171c71c9031755f8cd7d83414875853009be9b554c93adfda13e932059118a309402e15e32b955f87917394842f2b822e877f64618770ae3236d66d3226e1c21f59d96c80e8066d120a51385ddeab749069acab4c3f3e8676352c8d4ef7e6fbd671980c9b0716b039c3c466a602556e318cf7ce08433f069cbf6a02bd24760f27682338abb69c56188034020479fbfe67beb5ef1c9da0c01824582dcdcafe9d774d7e57d0b45794ce7d015b7e7b28f769c8523e32115a8b0931114719de21627d1fac379ac69d88239de9da37c27751b7de553106ce12337eacc7e8b8b98214879492e8cec613d8cdd2cf0c64e1904405332f02d919f54e2350954c86d4a8ebbc79a3b23cadc051301b783defdd6d4dc6819fd6ce1bec8169752711502c952f03018df95d7af95c18dfa9c13315ee9b231336a068c11388207d45244124fd24ea5ba505f05cf37742e680d0cd5d53b08d5451bb86710f3cb1bb798dedc107e3a8c0ae95b5511be6d3f1bdb6f5fa40c437812a5c2c8e912b9b55550dafafb5a7d2f36a89f96821e0105f3c2e341898721eb2ecd8cbbfeb22024bc308de60758af
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145571);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2021-0208");
  script_xref(name:"JSA", value:"JSA11098");
  script_xref(name:"IAVA", value:"2021-A-0036-S");

  script_name(english:"Juniper Junos OS Denial of Service (JSA11098)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11098
advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  # https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/disable-edit-protocols-rsvp.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd50bdea");
  # https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/corouted-bidirectional-edit-protocols-mpls.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9fda3805");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11098");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11098");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0208");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

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

model = get_kb_item_or_exit('Host/Juniper/model');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'1.0',	'fixed_ver':'15.1X49-D240', 'model':"^SRX"},
  {'min_ver':'1.0',	'fixed_ver':'17.3R3-S10'},
  {'min_ver':'17.4',	'fixed_ver':'17.4R3-S2'},
  {'min_ver':'18.1',	'fixed_ver':'18.1R3-S10'},
  {'min_ver':'18.2',	'fixed_ver':'18.2R2-S7'},
  {'min_ver':'18.3',	'fixed_ver':'18.3R3-S2'},
  {'min_ver':'18.4',	'fixed_ver':'18.4R1-S8'},
  {'min_ver':'19.1',	'fixed_ver':'19.1R1-S5'},
  {'min_ver':'19.2',	'fixed_ver':'19.2R3'},
  {'min_ver':'19.3',	'fixed_ver':'19.3R2-S5'},
  {'min_ver':'19.4',	'fixed_ver':'19.4R2-S2'},
  {'min_ver':'20.1',	'fixed_ver':'20.1R1-S4'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
override = TRUE;

# https://www.juniper.net/documentation/en_US/junos/topics/topic-map/basic-lsp-configurtion.html
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
  {
    override = FALSE;
    if (!junos_check_config(buf:buf, pattern:"label-switched-path.*corouted-bidirectional"))
      audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
  }
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);
