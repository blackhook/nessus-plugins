#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133471);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/27");

  script_cve_id("CVE-2019-9853");

  script_name(english:"LibreOffice 6.2.6 / 6.3.1 Security Control Bypass (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"An issue with how LibreOffice handles URL decoding can lead to the execution of macros that would otherwise be restricted
by inbuilt access controls.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the LibreOffice application running on the remote host is prior to 6.2.6.
It is, therefore, affected by a flaw in how LibreOffice sanitizes user supplied input when decoding URL encoded characters
in the macro location. This can result in macros within a document to be executed without the users knowledge.
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.libreoffice.org/about-us/security/advisories/CVE-2019-9853
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be7c8066");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 6.2.6, 6.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9853");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
app_info = vcf::get_app_info(app:'LibreOffice');

constraints = [
  {'min_version':'1.0', 'fixed_version':'6.2.6'},
  {'min_version':'3.0', 'fixed_version':'3.1'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
