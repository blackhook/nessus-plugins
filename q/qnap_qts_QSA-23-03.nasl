#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174226);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id("CVE-2022-42898");

  script_name(english:"QNAP QTS Buffer Overflow Vulnerability in Samba (QSA-23-03)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS installed on the remote host is affected by a buffer overflow vulnerability as referenced in 
the QSA-23-03 advisory. PAC parsing in MIT Kerberos 5 (aka krb5) before 1.19.4 and 1.20.x before 1.20.1 has integer 
overflows that may lead to remote code execution (in KDC, kadmind, or a GSS or Kerberos application server) on 32-bit
platforms (which have a resultant heap-based buffer overflow), and cause a denial of service on other platforms. This 
occurs in krb5_pac_parse in lib/krb5/krb/pac.c. Heimdal before 7.7.1 has a similar bug.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/QSA-23-03");
  script_set_attribute(attribute:"solution", value:
"Apply the solution referenced in the QSA-23-03 advisory");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42898");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:qts");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_qts_quts_hero_web_detect.nbin", "qnap_qts_installed.nbin");
  script_require_ports("installed_sw/QNAP QTS");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_qnap.inc');

var app_info = vcf::qnap::get_app_info();

var constraints = [
  {'product':'QTS', 'max_version':'5.0.1', 'Number':'2346', 'Build':'20230322', 'fixed_display':'QTS 5.0.1.2346 build 20230322'}
];
vcf::qnap::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
