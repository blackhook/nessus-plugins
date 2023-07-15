#TRUSTED 384a967a81b9ccb57fbaa29fc309fc8a955b9a82718b859158d1933f8c291135a8c8ba1147727540f3da0b962544ae6e1fa303b15465bd00e931dfa8621ca965e7a50b6fbac5ef89a3508f5dae4c03273f8759d8e47d6763ddc4dc3fae5f7ff6b22edc64943eb58668b6040212e67080d5d8c3d848e4a7e0f6779fc5ab616dea6ec88c9d476a096ec9ce15d22711b461888af4b295b8a15b34385b6b1836ff5c477745d48b5dd83e8f40763424e0a3c5ccbc9611ff4cb64ed58dee16c8a61a0f8023deebfbff5d55ce97d838d5343f078a04454a2ba50f04aedf84be92559ea764ec949362360bb4360fd870a9a400cc47fc16051feff586619eb342f51cfa65fd79634e83b168bbf0fb3e1fc87a96264103a1dc1d08319d1cc56a0556c1da486e9466cda432251bcc23d3ec8c71d0ed4a7782493935fe93a6423360759b05a3fa96dc877f30c78ae56849e4d6d10dfbbf7cd39863f9763c47038c92b9dd7ccdb7bcc316422610626d37c8dd4ed8c4a384c2445191c4bd9b6f0769a3edb4d1a7c9d3066c305643c51605f62e385194ac6a4808c49b3bbaf992a297efab24b85968cc87918b3103976d1090425820e795650ba45460212c5255dc8ba2754231a3a3c07cc3751e30822c5b07fbb8b5f846d46721909ecafe44bd6e0d5c00cbd9041cfc3949a255faae9823554d65a7a38c9dacf910d581390c4e559b21535c5292
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166379);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/24");

  script_cve_id("CVE-2022-22248");
  script_xref(name:"JSA", value:"JSA69905");
  script_xref(name:"IAVA", value:"2022-A-0421");

  script_name(english:"Juniper Junos OS Arbitrary Command Execution (JSA69905)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by an arbitrary command execution vulnerability as
referenced in the JSA69905 advisory. An Incorrect Permission Assignment vulnerability in shell processing of Juniper
Networks Junos OS Evolved allows a low-privileged local user to modify the contents of a configuration file which could
cause another user to execute arbitrary commands within the context of the follow-on user's session. If the follow-on
user is a high-privileged administrator, the attacker could leverage this vulnerability to take complete control of the
target system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-Evolved-Incorrect-file-permissions-can-allow-low-privileged-user-to-cause-another-user-to-execute-arbitrary-commands-CVE-2022-22248
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b2b5d3d");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69905");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22248");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/21");

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
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'20.4-EVO', 'fixed_ver':'20.4R3-S1-EVO'},
  {'min_ver':'21.1-EVO', 'fixed_ver':'21.2R3-EVO'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);