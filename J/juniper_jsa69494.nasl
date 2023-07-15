#TRUSTED 52d1dea7cd66b3821d8ea9da765b2a7fa1b351ed81aaaa6f020092577ea5be1e092e9c790316f0011329739fa9ab1c6c6da6f50179805e3ef4e378b145f1f9e9e92652190533330628f6c7f5d97ed1f3352c657fd4c2d6b1a2d73857f7ce5d77ef737dd74a053e276bd03ae5cb94303f150fca15c562423c750cb1df5ca76c48fad21b1ade3760c4961aefb2237d5df923ce304b88961a20d863b8db9c1a7bdee0a2bfe3a84643ac79767b69827bec3a94b51f94924f22fbcdd5085dd49d0c6791ec06564bd9a092ccbaee0769ef2c8155265211da07533bf2e1e78ce63fef4fd471155dd803759758b04bd89aa29ea189606130a1399c833b757663bf5d1c3c3fa02544344fe13989100872709bd4964a8507ad1638d600a9f60084e168bfa4c4919ee2a5860d8fc72ba1d3475f705a20f43c665ed24b11f76a7ee5e978dbc6ad40c66684ebb147e0d7d48ba5aee830429f04664e4998976d092369e4fc3f74d78867fae054ed4c24193bf4ae6fb9b7be310c3abc8ce18497287b32d5586345bd92d91ebbafd694424cda08c6702937158882ac6566692b357b4a1065dbe7df7d1df7f77ff6807d461d07a617627065002f2ded70ba701cf6b1588e426ec982c844e74e4a3f5c90f028d9da94d2119620bf5612a4b747ba3bb454fe83baa0f57a4cf063131c1139c1bedb309a4bee335b6a9e53597b1ed9427c3c21dc58acb6
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161217);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2022-22186");
  script_xref(name:"JSA", value:"JSA69494");
  script_xref(name:"IAVA", value:"2022-A-0162");

  script_name(english:"Juniper Junos OS Vulnerability (JSA69494)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69494
advisory.

  - Due to an Improper Initialization vulnerability in Juniper Networks Junos OS on EX4650 devices, packets
    received on the management interface (em0) but not destined to the device, may be improperly forwarded to
    an egress interface, instead of being discarded. Such traffic being sent by a client may appear genuine,
    but is non-standard in nature and should be considered as potentially malicious. This issue affects:
    Juniper Networks Junos OS on EX4650 Series: All versions prior to 19.1R3-S8; 19.2 versions prior to
    19.2R3-S5; 19.3 versions prior to 19.3R3-S5; 19.4 versions prior to 19.4R3-S7; 20.1 versions prior to
    20.1R3-S3; 20.2 versions prior to 20.2R3-S4; 20.3 versions prior to 20.3R3-S3; 20.4 versions prior to
    20.4R3-S2; 21.1 versions prior to 21.1R3-S1; 21.2 versions prior to 21.2R3; 21.3 versions prior to 21.3R2;
    21.4 versions prior to 21.4R2; 22.1 versions prior to 22.1R1. (CVE-2022-22186)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2022-04-Security-Bulletin-Junos-OS-EX4650-Series-Certain-traffic-received-by-the-Junos-OS-device-on-the-management-interface-may-be-forwarded-to-egress-interfaces-instead-of-discarded-CVE-2022-22186
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff8efb3b");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69494");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22186");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (model !~ "^EX465")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var vuln_ranges = [
  {'min_ver':'0',    'fixed_ver':'19.1R3-S8', 'model':'^EX465'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S5', 'model':'^EX465'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S5', 'model':'^EX465'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S7', 'model':'^EX465'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S3', 'model':'^EX465'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S4', 'model':'^EX465'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S3', 'model':'^EX465'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S2', 'model':'^EX465'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S1', 'model':'^EX465'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3', 'model':'^EX465'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R2', 'model':'^EX465'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2', 'model':'^EX465'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var report = get_report(ver:ver, fix:fix, model:model);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
