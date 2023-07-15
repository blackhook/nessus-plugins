#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139240);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2020-15523");
  script_xref(name:"IAVA", value:"2020-A-0340-S");

  script_name(english:"Python DLL Loading Local Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Python installed on the remote Windows host is 3.6.x prior to 3.6.12, 3.7.x prior to 3.7.9, 3.8.x prior
to 3.8.4, or 3.9.x prior to 3.9.0b5. It is, therefore, affected by an elevation of privilege vulnerability. A Trojan 
horse python3.dll might be used in cases where CPython is embedded in a native application. This occurs because 
python3X.dll may use an invalid search path for python3.dll loading (after Py_SetPath has been used).");
  script_set_attribute(attribute:"see_also", value:"https://bugs.python.org/issue29778");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Python 3.6.12, 3.7.9, 3.8.4, 3.9.0b5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:python:python");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("python_win_installed.nbin");
  script_require_keys("installed_sw/Python Software Foundation Python", "SMB/Registry/Enumerated", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Python Software Foundation Python', win_local:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  {'min_version':'3.6', 'fixed_version' : '3.6.12000', 'fixed_display':'3.6.12' },
  {'min_version':'3.7', 'fixed_version' : '3.7.9000', 'fixed_display':'3.7.9' },
  {'min_version':'3.8', 'fixed_version' : '3.8.4150.1013', 'fixed_display':'3.8.4' },
  {'min_version':'3.9', 'fixed_version' : '3.9.115.1013', 'fixed_display':'3.9.0b5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
