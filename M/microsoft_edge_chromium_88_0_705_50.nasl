##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145448);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/17");

  script_cve_id(
    "CVE-2020-16044",
    "CVE-2021-21118",
    "CVE-2021-21119",
    "CVE-2021-21120",
    "CVE-2021-21121",
    "CVE-2021-21122",
    "CVE-2021-21123",
    "CVE-2021-21124",
    "CVE-2021-21125",
    "CVE-2021-21126",
    "CVE-2021-21127",
    "CVE-2021-21128",
    "CVE-2021-21129",
    "CVE-2021-21130",
    "CVE-2021-21131",
    "CVE-2021-21132",
    "CVE-2021-21133",
    "CVE-2021-21134",
    "CVE-2021-21135",
    "CVE-2021-21136",
    "CVE-2021-21137",
    "CVE-2021-21139",
    "CVE-2021-21140",
    "CVE-2021-21141"
  );

  script_name(english:"Microsoft Edge (Chromium) < 88.0.705.50 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 88.0.705.50. It is, therefore, affected
by multiple vulnerabilities. Note that Nessus has not tested for this issue but has instead relied only on the
application's self-reported version number.");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-16044
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f11ddceb");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21118
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e38b0261");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21119
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?956993df");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21120
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86ccd1a7");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21121
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea65fbbf");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21122
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d945c5fd");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21123
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?804c6012");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21124
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6df00137");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21125
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e925c70");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21126
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f33d1708");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21127
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e453c1c0");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21128
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d644083b");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21129
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04560b20");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21130
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3dbc72e7");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21131
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3be82d62");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21132
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?776bc7e6");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21133
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?858149b3");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21134
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3838b7fb");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21135
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c282efb");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-21136
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1321a9c");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-21137
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?970b384a");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-21139
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6495027");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-21140
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef57ee24");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-21141
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a674cb6c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 88.0.705.50 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21132");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);
constraints = [
  { 'fixed_version' : '88.0.705.50' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
