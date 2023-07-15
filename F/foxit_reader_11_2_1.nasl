#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157229);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-1285",
    "CVE-2021-40420",
    "CVE-2021-44708",
    "CVE-2021-44709",
    "CVE-2021-44740",
    "CVE-2021-44741",
    "CVE-2022-22150",
    "CVE-2022-24357",
    "CVE-2022-24358",
    "CVE-2022-24359",
    "CVE-2022-24360",
    "CVE-2022-24361",
    "CVE-2022-24362",
    "CVE-2022-24363",
    "CVE-2022-24364",
    "CVE-2022-24365",
    "CVE-2022-24366",
    "CVE-2022-24367",
    "CVE-2022-24368",
    "CVE-2022-24369",
    "CVE-2022-24907",
    "CVE-2022-24908",
    "CVE-2022-24954",
    "CVE-2022-24955",
    "CVE-2022-24971",
    "CVE-2022-25108"
  );
  script_xref(name:"IAVA", value:"2022-A-0013-S");
  script_xref(name:"IAVA", value:"2022-A-0091-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Foxit PDF Reader < 11.2.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Reader application (previously named Foxit Reader) installed on the remote
Windows host is prior to 11.2.1. It is, therefore affected by multiple vulnerabilities:

  - Acrobat Reader DC version 21.007.20099 (and earlier), 20.004.30017 (and earlier) and 17.011.30204 (and
    earlier) are affected by a heap overflow vulnerability due to insecure handling of a crafted file,
    potentially resulting in arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2021-44708,
    CVE-2021-44709)

  - Acrobat Reader DC version 21.007.20099 (and earlier), 20.004.30017 (and earlier) and 17.011.30204 (and
    earlier) are affected by a Null pointer dereference vulnerability when parsing a specially crafted file.
    An unauthenticated attacker could leverage this vulnerability to achieve an application denial-of-service
    in the context of the current user. Exploitation of this issue requires user interaction in that a victim
    must open a malicious file. (CVE-2021-44740, CVE-2021-44741)

  - Apache log4net versions before 2.0.10 do not disable XML external entities when parsing log4net
    configuration files. This allows for XXE-based attacks in applications that accept attacker-controlled
    log4net configuration files. (CVE-2018-1285)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Reader version 11.2.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44709");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-24955");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Foxit Reader', win_local:TRUE);

var constraints = [
  { 'max_version' : '11.1.0.52543', 'fixed_version' : '11.2.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
