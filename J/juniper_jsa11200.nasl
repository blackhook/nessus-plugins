#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151636);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-0283", "CVE-2021-0284");
  script_xref(name:"JSA", value:"JSA11200");
  script_xref(name:"IAVA", value:"2021-A-0324-S");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA11200)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA11200 advisory.

  - A buffer overflow vulnerability in the TCP/IP stack of Juniper Networks Junos OS allows an attacker to
    send specific sequences of packets to the device thereby causing a Denial of Service (DoS). By repeatedly
    sending these sequences of packets to the device, an attacker can sustain the Denial of Service (DoS)
    condition. The device will abnormally shut down as a result of these sent packets. A potential indicator
    of compromise will be the following message in the log files: eventd[13955]: SYSTEM_ABNORMAL_SHUTDOWN:
    System abnormally shut down These issue are only triggered by traffic destined to the device. Transit
    traffic will not trigger these issues. (CVE-2021-0283, CVE-2021-0284)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11200");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11200");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0284");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'12.3',   'fixed_ver':'12.3R12-S19'},
  {'min_ver':'15.1',   'fixed_ver':'15.1R7-S10'},
  {'min_ver':'16.1R1', 'fixed_ver':'16.3',      'fixed_display' : 'See vendor advisory'},
  {'min_ver':'17.1R1', 'fixed_ver':'17.2R9999', 'fixed_display' : 'See vendor advisory'},
  {'min_ver':'17.3',   'fixed_ver':'17.3R3-S12'},
  {'min_ver':'17.4R1', 'fixed_ver':'17.5',      'fixed_display' : 'See vendor advisory'},
  {'min_ver':'18.1',   'fixed_ver':'18.1R3-S13'},
  {'min_ver':'18.2R1', 'fixed_ver':'18.2R9999', 'fixed_display' : 'See vendor advisory'},
  {'min_ver':'18.3',   'fixed_ver':'18.3R3-S5'},
  {'min_ver':'18.4',   'fixed_ver':'18.4R3-S9'},
  {'min_ver':'19.1',   'fixed_ver':'19.1R3-S7'},
  {'min_ver':'19.2',   'fixed_ver':'19.2R3-S3'},
  {'min_ver':'19.3',   'fixed_ver':'19.3R3-S3'},
  {'min_ver':'19.4',   'fixed_ver':'19.4R3-S5'},
  {'min_ver':'20.1',   'fixed_ver':'20.1R3-S1'},
  {'min_ver':'20.2',   'fixed_ver':'20.2R3-S2'},
  {'min_ver':'20.3',   'fixed_ver':'20.3R3-S1'},
  {'min_ver':'20.4',   'fixed_ver':'20.4R2-S2', 'fixed_display':'20.4R2-S2 / 20.4R3'},
  {'min_ver':'21.1',   'fixed_ver':'21.1R2'},
  {'min_ver':'21.2',   'fixed_ver':'21.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
