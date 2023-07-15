#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156198);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id("CVE-2021-3737");
  script_xref(name:"IAVA", value:"2021-A-0497-S");

  script_name(english:"Python < 3.6.14 / 3.7.11 / 3.8.11 / 3.9.6 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"A denial of service vulnerability exists in Python 3.6.x < 3.6.14, 3.7.x < 3.7.11, 3.8.x < 3.8.11, and
3.9.x < 3.9.6.  If a client performs an HTTP/HTTPS/FTP request against a service controlled by an attacker,
the attacker can make this client hang forever, even if the client has set a timeout argument (CVE-2021-3737).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.python.org/issue44022");
  script_set_attribute(attribute:"solution", value:
"Upgrade Python to 3.6.14, 3.7.11, 3.8.11, 3.9.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3737");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:python:python");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("python_win_installed.nbin");
  script_require_keys("installed_sw/Python Software Foundation Python", "SMB/Registry/Enumerated", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Python Software Foundation Python', win_local:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  {'min_version':'3.6', 'fixed_version' : '3.6.14000', 'fixed_display':'3.6.14' },
  {'min_version':'3.7', 'fixed_version' : '3.7.11000', 'fixed_display':'3.7.11' },
  {'min_version':'3.8', 'fixed_version' : '3.8.11000', 'fixed_display':'3.8.11' },
  {'min_version':'3.9', 'fixed_version' : '3.9.6150.1013', 'fixed_display':'3.9.6150.1013' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
