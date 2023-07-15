##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145534);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/04");

  script_cve_id("CVE-2021-3177");
  script_xref(name:"IAVA", value:"2021-A-0052-S");

  script_name(english:"Python Buffer Overflow (CVE-2021-3177)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Python installed on the remote Windows host is potentially affected by a buffer overflow in PyCArg_repr
in _ctypes/callproc.c, which may lead to remote code execution in certain Python applications that accept floating-point
numbers as untrusted input, as demonstrated by a 1e300 argument to c_double.from_param. This occurs because sprintf is
used unsafely.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.python.org/issue42938");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3177");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:python:python");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("python_win_installed.nbin");
  script_require_keys("installed_sw/Python Software Foundation Python", "SMB/Registry/Enumerated", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Python Software Foundation Python', win_local:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  {'min_version':'3.6', 'max_version' : '3.6.12000', 'fixed_display':'See vendor advisory' },
  {'min_version':'3.7', 'max_version' : '3.7.9150.1013', 'fixed_display':'See vendor advisory' },
  {'min_version':'3.8', 'max_version' : '3.8.7150.1013', 'fixed_display':'See vendor advisory' },
  {'min_version':'3.9', 'max_version' : '3.9.1150.1013', 'fixed_display':'See vendor advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
