##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163769);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2022-22209");
  script_xref(name:"IAVA", value:"2022-A-0280");
  script_xref(name:"JSA", value:"JSA69713");

  script_name(english:"Juniper Junos OS Vulnerability (JSA69713)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69713
advisory.    - A Missing Release of Memory after Effective Lifetime vulnerability in the kernel of Juniper Networks
Junos     OS allows an unauthenticated network based attacker to cause a Denial of Service (DoS). On all Junos
platforms, the Kernel Routing Table (KRT) queue can get stuck due to a memory leak triggered by interface     flaps or
route churn leading to RIB and PFEs getting out of sync. The memory leak causes RTNEXTHOP/route     and next-hop memory
pressure issue and the KRT queue will eventually get stuck with the error- 'ENOMEM --     Cannot allocate memory'. The
out-of-sync state between RIB and FIB can be seen with the show route and     show route forwarding-table command. This
issue will lead to failures for adding new routes. The KRT     queue status can be checked using the CLI command show
krt queue: user@host > show krt state High-     priority add queue: 1 queued ADD nhtype Router index 0 (31212) error
'ENOMEM -- Cannot allocate memory'     kqp '0x8ad5e40' The following messages will be observed in /var/log/messages,
which indicate high memory     for routes/nexthops: host rpd[16279]: RPD_RT_HWM_NOTICE: New RIB highwatermark for
routes: 266 [2022-03-04     05:06:07] host rpd[16279]: RPD_KRT_Q_RETRIES: nexthop ADD: Cannot allocate memory host
rpd[16279]:     RPD_KRT_Q_RETRIES: nexthop ADD: Cannot allocate memory host kernel: rts_veto_net_delayed_unref_limit:
Route/nexthop memory is severe pressure. User Application to perform recovery actions. O p 8 err 12,     rtsm_id 0:-1,
msg type 10, veto simulation: 0. host kernel: rts_veto_net_delayed_unref_limit: Memory usage     of M_RTNEXTHOP type =
(806321208) Max size possible for M_RTNEXTHOP type = (689432176) Current delayed     unref = (0), Max delayed unref on
this platform = (120000) Current delayed weight unref = (0) Max delayed     weight unref on this platform = (400000)
curproc = rpd. This issue affects: Juniper Networks Junos OS 21.2     versions prior to 21.2R3; 21.3 versions prior to
21.3R2-S1, 21.3R3; 21.4 versions prior to 21.4R1-S2,     21.4R2; This issue does not affect Juniper Networks Junos OS
versions prior to 21.2R1. (CVE-2022-22209)  Note that Nessus has not tested for this issue but has instead relied only
on the application's self-reported version number.);   # http://www.nessus.org/u?99086ea4
script_set_attribute(attribute:see_also, value:http://www.nessus.org/u?99086ea4);   # http://www.nessus.org/u?b616ed59
script_set_attribute(attribute:see_also, value:http://www.nessus.org/u?b616ed59);   # http://www.nessus.org/u?0d4fd08b
script_set_attribute(attribute:see_also, value:http://www.nessus.org/u?0d4fd08b);   # http://www.nessus.org/u?553f364c
script_set_attribute(attribute:see_also, value:http://www.nessus.org/u?553f364c");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2022-07-Security-Bulletin-Junos-OS-RIB-and-PFEs-can-get-out-of-sync-due-to-a-memory-leak-caused-by-interface-flaps-or-route-churn-CVE-2022-22209
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?553f364c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69713");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22209");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'21.2', 'fixed_ver':'21.2R3'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R2-S1', 'fixed_display':'21.3R2-S1, 21.3R3'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R1-S2', 'fixed_display':'21.4R1-S2, 21.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
