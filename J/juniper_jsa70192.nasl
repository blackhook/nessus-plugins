#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177295);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/14");

  script_cve_id("CVE-2023-22396");
  script_xref(name:"JSA", value:"JSA70192");
  script_xref(name:"IAVA", value:"2023-A-0041");

  script_name(english:"Juniper Junos OS Vulnerability (JSA70192)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA70192
advisory. An Uncontrolled Resource Consumption vulnerability in TCP processing on the Routing Engine (RE) of Juniper
Networks Junos OS allows an unauthenticated network-based attacker to send crafted TCP packets destined to the device,
resulting in an MBUF leak that ultimately leads to a Denial of Service (DoS). The system does not recover automatically
and must be manually restarted to restore service. This issue occurs when crafted TCP packets are sent directly to a
configured IPv4 or IPv6 interface on the device. Transit traffic will not trigger this issue. MBUF usage can be
monitored through the use of the 'show system buffers' command. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process?r=65&ui-knowledge-components-aura-actions.KnowledgeArticleVersionCreateDraftFromOnlineAction.createDraftFromOnlineArticle=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?638b86fc");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed?r=65&ui-knowledge-components-aura-actions.KnowledgeArticleVersionCreateDraftFromOnlineAction.createDraftFromOnlineArticle=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c980b637");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories?r=65&ui-knowledge-components-aura-actions.KnowledgeArticleVersionCreateDraftFromOnlineAction.createDraftFromOnlineArticle=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f8cb861");
  # https://supportportal.juniper.net/s/article/2023-01-Security-Bulletin-Junos-OS-Receipt-of-crafted-TCP-packets-on-Ethernet-console-port-results-in-MBUF-leak-leading-to-Denial-of-Service-DoS-CVE-2023-22396
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8efd3d1c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA70192");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22396");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/14");

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
  {'min_ver':'12.3R12-S19', 'fixed_ver':'12.3R999-S999', 'fixed_display':'See vendor advisory'},
  {'min_ver':'15.1R7-S10', 'fixed_ver':'15.1R999-S999', 'fixed_display':'See vendor advisory'},
  {'min_ver':'17.3R3-S12', 'fixed_ver':'17.3R999-S999', 'fixed_display':'See vendor advisory'},
  {'min_ver':'18.4R3-S9', 'fixed_ver':'18.4R999-S999', 'fixed_display':'See vendor advisory'},
  {'min_ver':'19.1R3-S7', 'fixed_ver':'19.1R999-S999', 'fixed_display':'See vendor advisory'},
  {'min_ver':'19.2R3-S3', 'fixed_ver':'19.2R999-S999', 'fixed_display':'See vendor advisory'},
  {'min_ver':'19.3R2-S7', 'fixed_ver':'19.3R2-S8', 'fixed_display':'19.3R3-S7'},
  {'min_ver':'19.3R3-S3', 'fixed_ver':'19.3R3-S7'},
  {'min_ver':'19.4R2-S7', 'fixed_ver':'19.4R2-S8', 'fixed_display':'19.4R3-S10'},
  {'min_ver':'19.4R3-S5', 'fixed_ver':'19.4R3-S10'},
  {'min_ver':'20.1R3-S1', 'fixed_ver':'20.1R999-S999'},
  {'min_ver':'20.2R3-S2', 'fixed_ver':'20.2R3-S6'},
  {'min_ver':'20.3R3-S1', 'fixed_ver':'20.3R3-S6'},
  {'min_ver':'20.4R2-S2', 'fixed_ver':'20.4R2-S3', 'fixed_display':'20.4R3-S5'},
  {'min_ver':'20.4R3', 'fixed_ver':'20.4R3-S5'},
  {'min_ver':'21.1R2', 'fixed_ver':'21.1R3-S4'},
  {'min_ver':'21.2R1-S1', 'fixed_ver':'21.2R1-S2', 'fixed_display':'21.2R3-S3'},
  {'min_ver':'21.2R2', 'fixed_ver':'21.2R3-S3'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S2'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R2-S1', 'fixed_display':'22.1R2-S1, 22.1R3'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R1-S2', 'fixed_display':'22.2R1-S2, 22.2R2'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R1-S1', 'fixed_display':'22.3R1-S1, 22.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
