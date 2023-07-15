#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154123);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-0283", "CVE-2021-31364");
  script_xref(name:"JSA", value:"JSA11226");
  script_xref(name:"IAVA", value:"2021-A-0324-S");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11226)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11226
advisory.

  - A buffer overflow vulnerability in the TCP/IP stack of Juniper Networks Junos OS allows an attacker to
    send specific sequences of packets to the device thereby causing a Denial of Service (DoS). By repeatedly
    sending these sequences of packets to the device, an attacker can sustain the Denial of Service (DoS)
    condition. The device will abnormally shut down as a result of these sent packets. A potential indicator
    of compromise will be the following message in the log files: eventd[13955]: SYSTEM_ABNORMAL_SHUTDOWN:
    System abnormally shut down These issue are only triggered by traffic destined to the device. Transit
    traffic will not trigger these issues. This issue affects: Juniper Networks Junos OS 12.3 versions prior
    to 12.3R12-S19; 15.1 versions prior to 15.1R7-S10; 16.1 version 16.1R1 and later versions; 16.2 version
    16.2R1 and later versions; 17.1 version 17.1R1 and later versions; 17.2 version 17.2R1 and later versions;
    17.3 versions prior to 17.3R3-S12; 17.4 version 17.4R1 and later versions; 18.1 versions prior to
    18.1R3-S13; 18.2 version 18.2R1 and later versions; 18.3 versions prior to 18.3R3-S5; 18.4 versions prior
    to 18.4R3-S9; 19.1 versions prior to 19.1R3-S6; 19.2 versions prior to 19.2R3-S3; 19.3 versions prior to
    19.3R3-S3; 19.4 versions prior to 19.4R1-S4, 19.4R3-S5; 20.1 versions prior to 20.1R2-S2, 20.1R3-S1; 20.2
    versions prior to 20.2R3-S2; 20.3 versions prior to 20.3R3; 20.4 versions prior to 20.4R2-S1, 20.4R3; 21.1
    versions prior to 21.1R1-S1, 21.1R2; 21.2 versions prior to 21.2R2. (CVE-2021-0283)

  - An Improper Check for Unusual or Exceptional Conditions vulnerability combined with a Race Condition in
    the flow daemon (flowd) of Juniper Networks Junos OS on SRX300 Series, SRX500 Series, SRX1500, and SRX5000
    Series with SPC2 allows an unauthenticated network based attacker sending specific traffic to cause a
    crash of the flowd/srxpfe process, responsible for traffic forwarding in SRX, which will cause a Denial of
    Service (DoS). Continued receipt and processing of this specific traffic will create a sustained Denial of
    Service (DoS) condition. This issue can only occur when specific packets are trying to create the same
    session and logging for session-close is configured as a policy action. Affected platforms are: SRX300
    Series, SRX500 Series, SRX1500, and SRX5000 Series with SPC2. Not affected platforms are: SRX4000 Series,
    SRX5000 Series with SPC3, and vSRX Series. This issue affects Juniper Networks Junos OS SRX300 Series,
    SRX500 Series, SRX1500, and SRX5000 Series with SPC2: All versions prior to 17.4R3-S5; 18.3 versions prior
    to 18.3R3-S5; 18.4 versions prior to 18.4R3-S9; 19.1 versions prior to 19.1R3-S6; 19.2 versions prior to
    19.2R1-S7, 19.2R3-S2; 19.3 versions prior to 19.3R2-S6, 19.3R3-S2; 19.4 versions prior to 19.4R1-S4,
    19.4R3-S3; 20.1 versions prior to 20.1R2-S2, 20.1R3; 20.2 versions prior to 20.2R3; 20.3 versions prior to
    20.3R2-S1, 20.3R3; 20.4 versions prior to 20.4R2. (CVE-2021-31364)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11226");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11226");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0283");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(SRX1500|SRX3|SRX5|SRX5000)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5', 'model':'^(SRX1500|SRX3|SRX5|SRX5000)'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R3-S9', 'model':'^(SRX1500|SRX3|SRX5|SRX5000)'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S6', 'model':'^(SRX1500|SRX3|SRX5|SRX5000)'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S7', 'model':'^(SRX1500|SRX3|SRX5|SRX5000)'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S2', 'model':'^(SRX1500|SRX3|SRX5|SRX5000)'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S6', 'model':'^(SRX1500|SRX3|SRX5|SRX5000)'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S2', 'model':'^(SRX1500|SRX3|SRX5|SRX5000)'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S4', 'model':'^(SRX1500|SRX3|SRX5|SRX5000)'},
  {'min_ver':'19.4R2', 'fixed_ver':'19.4R3-S3', 'model':'^(SRX1500|SRX3|SRX5|SRX5000)'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S2', 'model':'^(SRX1500|SRX3|SRX5|SRX5000)', 'fixed_display':'20.1R2-S2, 20.1R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3', 'model':'^(SRX1500|SRX3|SRX5|SRX5000)'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R2-S1', 'model':'^(SRX1500|SRX3|SRX5|SRX5000)', 'fixed_display':'20.3R2-S1, 20.3R3'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R2', 'model':'^(SRX1500|SRX3|SRX5|SRX5000)'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
