#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136828);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/13");

  script_cve_id("CVE-2020-1632");
  script_xref(name:"JSA", value:"JSA11013");
  script_xref(name:"IAVA", value:"2020-A-0162-S");

  script_name(english:"Junos OS Invalid BGP Update Termination Denial Of Service Vulnerability (JSA11013)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is prior to 16.1R7-S6, 16.2R2-S11, 17.1R2-S11, 17.2R1-S9,
17.2X75-D105, 17.3R2-S5, 17.4R2-S8, 18.1R3-S8, 18.2R2-S6, 18.2X75-D12, 18.3R1-S6, 18.4R1-S5, 19.1R1-S3, or 19.2R1-S2.
It is, therefore, affected by a denial of service (DoS) vulnerability. An unauthenticated, remote attacker can exploit
this, by sending a specific BGP UPDATE message, in order to cause other peers to terminate the established BGP session 
as referenced in the JSA11013 advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11013");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11013");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1632");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

#This issue does not affect Juniper Networks Junos OS prior to 16.1R1.
vuln_ranges = [
  {'min_ver':'16.1R1',   'fixed_ver':'16.1R7-S6'},
  {'min_ver':'16.2',   'fixed_ver':'16.2R2-S11'},
  {'min_ver':'17.1',   'fixed_ver':'17.1R2-S11'},
  {'min_ver':'17.1R3',   'fixed_ver':'17.1R3-S2'},
  {'min_ver':'17.2',   'fixed_ver':'17.2R1-S9'},
  {'min_ver':'17.2R2',   'fixed_ver':'17.2R2-S8'},
  {'min_ver':'17.2R3',   'fixed_ver':'17.2R3-S3'},
  {'min_ver':'17.2X75',   'fixed_ver':'17.2X75-D44'},
  {'min_ver':'17.3',   'fixed_ver':'17.3R2-S5'},
  {'min_ver':'17.3R3',   'fixed_ver':'17.3R3-S7'},
  {'min_ver':'17.4R',   'fixed_ver':'17.4R2-S8'},
  {'min_ver':'18.1',   'fixed_ver':'18.1R3-S8'},
  {'min_ver':'18.2',   'fixed_ver':'18.2R2-S6'},
  {'min_ver':'18.2R3',   'fixed_ver':'18.2R3-S2'},
  {'min_ver':'18.2X75',   'fixed_ver':'18.2X75-D12'},
  {'min_ver':'18.3',   'fixed_ver':'18.3R1-S6'},
  {'min_ver':'18.3R2',   'fixed_ver':'18.3R2-S3'},
  {'min_ver':'18.4',   'fixed_ver':'18.4R1-S5'},
#18.4 version 18.4R2 and later versions;
  {'min_ver':'18.4R2',   'fixed_ver':'18.4R3'},
  {'min_ver':'19.1',   'fixed_ver':'19.1R1-S3'},
  {'min_ver':'19.2',   'fixed_ver':'19.2R1-S2'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);