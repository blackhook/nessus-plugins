#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156687);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/24");

  script_cve_id("CVE-2022-22174");
  script_xref(name:"JSA", value:"JSA11280");
  script_xref(name:"IAVA", value:"2022-A-0022");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11280)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11280
advisory.

  - A vulnerability in the processing of inbound IPv6 packets in Juniper Networks Junos OS on QFX5000 Series
    and EX4600 switches may cause the memory to not be freed, leading to a packet DMA memory leak, and
    eventual Denial of Service (DoS) condition. Once the condition occurs, further packet processing will be
    impacted, creating a sustained Denial of Service (DoS) condition. The following error logs may be observed
    using the show heap command and the device may eventually run out of memory if such packets are received
    continuously. Jan 12 12:00:00 device-name fpc0 (buf alloc) failed allocating packet buffer Jan 12 12:00:01
    device-name fpc0 (buf alloc) failed allocating packet buffer user@device-name> request pfe execute target
    fpc0 timeout 30 command show heap ID Base Total(b) Free(b) Used(b) % Name -- ---------- -----------
    ----------- ----------- --- ----------- 0 246fc1a8 536870488 353653752 183216736 34 Kernel 1 91800000
    16777216 12069680 4707536 28 DMA 2 92800000 75497472 69997640 5499832 7 PKT DMA DESC 3 106fc000 335544320
    221425960 114118360 34 Bcm_sdk 4 97000000 176160768 200 176160568 99 Packet DMA <<<<<<<<<<<<<< 5 903fffe0
    20971504 20971504 0 0 Blob This issue affects Juniper Networks Junos OS on QFX5000 Series, EX4600: 18.3R3
    versions prior to 18.3R3-S6; 18.4 versions prior to 18.4R2-S9, 18.4R3-S9; 19.1 versions prior to
    19.1R2-S3, 19.1R3-S7; 19.2 versions prior to 19.2R1-S8, 19.2R3-S3; 19.3 versions prior to 19.3R2-S7,
    19.3R3-S4; 19.4 versions prior to 19.4R2-S5, 19.4R3-S6; 20.1 versions prior to 20.1R3-S1; 20.2 versions
    prior to 20.2R3-S2; 20.3 versions prior to 20.3R3-S1; 20.4 versions prior to 20.4R3; 21.1 versions prior
    to 21.1R2-S1, 21.1R3; 21.2 versions prior to 21.2R1-S1, 21.2R2. This issue does not affect Juniper
    Networks Junos OS: Any versions prior to 17.4R3; 18.1 versions prior to 18.1R3-S6; 18.2 versions prior to
    18.2R3; 18.3 versions prior to 18.3R3; 18.4 versions prior to 18.4R2; 19.1 versions prior to 19.1R2.
    (CVE-2022-22174)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11280");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11280");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22174");

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
if (model !~ "^(EX4600|QFX5)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S6', 'model':'^(EX4600|QFX5)'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3', 'model':'^(EX4600|QFX5)'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3', 'model':'^(EX4600|QFX5)'},
  {'min_ver':'18.3R3', 'fixed_ver':'18.3R3-S6', 'model':'^(EX4600|QFX5)'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2', 'model':'^(EX4600|QFX5)', 'fixed_display':'18.4R2, 18.4R2-S9'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S9', 'model':'^(EX4600|QFX5)'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R2', 'model':'^(EX4600|QFX5)', 'fixed_display':'19.1R2, 19.1R2-S3'},
  {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S7', 'model':'^(EX4600|QFX5)'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S8', 'model':'^(EX4600|QFX5)'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S3', 'model':'^(EX4600|QFX5)'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S7', 'model':'^(EX4600|QFX5)'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S4', 'model':'^(EX4600|QFX5)'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S5', 'model':'^(EX4600|QFX5)'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S6', 'model':'^(EX4600|QFX5)'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S1', 'model':'^(EX4600|QFX5)'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S2', 'model':'^(EX4600|QFX5)'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S1', 'model':'^(EX4600|QFX5)'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3', 'model':'^(EX4600|QFX5)'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2-S1', 'model':'^(EX4600|QFX5)', 'fixed_display':'21.1R2-S1, 21.1R3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R1-S1', 'model':'^(EX4600|QFX5)', 'fixed_display':'21.2R1-S1, 21.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
