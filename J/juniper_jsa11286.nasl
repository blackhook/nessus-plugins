#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156675);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/24");

  script_cve_id("CVE-2022-22180");
  script_xref(name:"JSA", value:"JSA11286");
  script_xref(name:"IAVA", value:"2022-A-0028");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11286)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11286
advisory.

  - An Improper Check for Unusual or Exceptional Conditions vulnerability in the processing of specific IPv6
    packets on certain EX Series devices may lead to exhaustion of DMA memory causing a Denial of Service
    (DoS). Over time, exploitation of this vulnerability may cause traffic to stop being forwarded, or a crash
    of the fxpc process. An indication of the issue occurring may be observed through the following log
    messages: Sep 13 17:14:59 hostname : %PFE-3: fpc0 (buf alloc) failed allocating packet buffer Sep 13
    17:14:59 hostname : %PFE-7: fpc0 brcm_pkt_buf_alloc:393 (buf alloc) failed allocating packet buffer When
    Packet DMA heap utilization reaches 99%, the system will become unstable. Packet DMA heap utilization can
    be monitored using the command: user@junos# request pfe execute target fpc0 timeout 30 command show heap
    ID Base Total(b) Free(b) Used(b) % Name -- ---------- ----------- ----------- ----------- --- -----------
    0 213301a8 536870488 387228840 149641648 27 Kernel 1 91800000 8388608 3735120 4653488 55 DMA 2 92000000
    75497472 74452192 1045280 1 PKT DMA DESC 3 d330000 335544320 257091400 78452920 23 Bcm_sdk 4 96800000
    184549376 2408 184546968 99 Packet DMA <<<< 5 903fffe0 20971504 20971504 0 0 Blob This issue affects:
    Juniper Networks Junos OS 18.4 versions prior to 18.4R2-S10, 18.4R3-S10 on EX2300 Series, EX2300-MP
    Series, EX3400 Series; 19.1 versions prior to 19.1R3-S7 on EX2300 Series, EX2300-MP Series, EX3400 Series;
    19.2 versions prior to 19.2R1-S8, 19.2R3-S4 on EX2300 Series, EX2300-MP Series, EX3400 Series; 19.3
    versions prior to 19.3R3-S5 on EX2300 Series, EX2300-MP Series, EX3400 Series; 19.4 versions prior to
    19.4R3-S7 on EX2300 Series, EX2300-MP Series, EX3400 Series; 20.1 versions prior to 20.1R3-S3 on EX2300
    Series, EX2300-MP Series, EX3400 Series; 20.2 versions prior to 20.2R3-S3 on EX2300 Series, EX2300-MP
    Series, EX3400 Series; 20.3 versions prior to 20.3R3-S2 on EX2300 Series, EX2300-MP Series, EX3400 Series;
    20.4 versions prior to 20.4R3-S1 on EX2300 Series, EX2300-MP Series, EX3400 Series; 21.1 versions prior to
    21.1R2-S2, 21.1R3 on EX2300 Series, EX2300-MP Series, EX3400 Series; 21.2 versions prior to 21.2R1-S2,
    21.2R2 on EX2300 Series, EX2300-MP Series, EX3400 Series; 21.3 versions prior to 21.3R1-S1, 21.3R2 on
    EX2300 Series, EX2300-MP Series, EX3400 Series. (CVE-2022-22180)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11286");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11286");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22180");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/12");

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

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(EX23|EX2300)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S10', 'model':'^(EX23|EX2300)'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S10', 'model':'^(EX23|EX2300)'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S7', 'model':'^(EX23|EX2300)'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S8', 'model':'^(EX23|EX2300)'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S4', 'model':'^(EX23|EX2300)'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S5', 'model':'^(EX23|EX2300)'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S7', 'model':'^(EX23|EX2300)'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S3', 'model':'^(EX23|EX2300)'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S3', 'model':'^(EX23|EX2300)'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S2', 'model':'^(EX23|EX2300)'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S1', 'model':'^(EX23|EX2300)'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2-S2', 'model':'^(EX23|EX2300)', 'fixed_display':'21.1R2-S2, 21.1R3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R1-S2', 'model':'^(EX23|EX2300)', 'fixed_display':'21.2R1-S2, 21.2R2'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R1-S1', 'model':'^(EX23|EX2300)', 'fixed_display':'21.3R1-S1, 21.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
