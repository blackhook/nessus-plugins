#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125147);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2016-1000031",
    "CVE-2017-9798",
    "CVE-2018-0161",
    "CVE-2018-0734",
    "CVE-2018-0735",
    "CVE-2018-1257",
    "CVE-2018-1258",
    "CVE-2018-5407",
    "CVE-2018-11039",
    "CVE-2018-11040",
    "CVE-2018-11763",
    "CVE-2018-15756"
  );
  script_bugtraq_id(
    93604,
    100872,
    103573,
    104222,
    104260,
    105414,
    105703,
    105750,
    105758,
    105897,
    107984,
    107986
  );
  script_xref(name:"IAVA", value:"2019-A-0130");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Enterprise Manager Ops Center (Apr 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Cloud Control installed on
the remote host is affected by multiple vulnerabilities in
Enterprise Manager Base Platform component:

  - A deserialization vulnerability in Apache Commons
    FileUpload allows for remote code execution.
    (CVE-2016-1000031)

  - An information disclosure vulnerability exists in OpenSSL
    due to the potential for a side-channel timing attack.
    An unauthenticated attacker can exploit this to disclose
    potentially sensitive information. (CVE-2018-0734)

  - A denial of service (DoS) vulnerability exists in Apache
    HTTP Server 2.4.17 to 2.4.34, due to a design error. An
    unauthenticated, remote attacker can exploit this issue
    by sending continuous, large SETTINGS frames to cause a
    client to occupy a connection, server thread and CPU
    time without any connection timeout coming to effect.
    This affects only HTTP/2 connections. A possible
    mitigation is to not enable the h2 protocol.
    (CVE-2018-11763).

  - Networking component of Enterprise Manager Base Platform
    (Spring Framework) is easily exploited and may allow an
    unauthenticated, remote attacker to takeover the
    Enterprise Manager Base Platform. (CVE-2018-1258)");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9166970d");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2019
Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1000031");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager_ops_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_ops_center_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Ops Center");

  exit(0);
}

include('vcf_extras_oracle_em_ops_center.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var constraints = [
  {'min_version': '12.3.3.0', 'max_version': '12.3.3.9999', 'uce_patch': '29623885', 'ui_patch': '29623898'}
];

var app_info = vcf::oracle_em_ops_center::get_app_info();

vcf::oracle_em_ops_center::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
