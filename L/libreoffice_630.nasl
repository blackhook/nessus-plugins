#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133474);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/19");

  script_cve_id("CVE-2019-9850", "CVE-2019-9851", "CVE-2019-9852");

  script_name(english:"LibreOffice < 6.2.6 / 6.3 Input Validation (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"A input validation vulnerability exists in  Document Foundation LibreOffice versions prior to 6.2.6 or 6.3.0 due to
insufficient URL encoding.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the LibreOffice application running on the remote host is prior to 6.2.6.
It is, therefore, affected by multiple vulnerabilities:
  - Protection that was added to mitigate CVE-2019-9848 which prevents LibreLogo from being called from a document event
    handler. However, insufficient validation of URL encoded characters could allow an attacker to bypass these protections
    and trigger LibreLogo from script event handlers. (CVE-2019-9850)

  - It is possible for documents to specify that pre-installed scripts be executed on global script events like document-open, etc. (CVE-2019-9851)

  - A feature of this application is that documents can make use of pre-installed macros that can be executed on various
    script events, the macros are supposed to only be able to access scripts in share/Scripts/python and user/Scripts/python
    sub-directories of the applications install. However, due to not properly sanitizing URL encoded characters this can be
    bypassed to allow execution of scripts in other directories. (CVE-2019-9852)
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.libreoffice.org/about-us/security/advisories/CVE-2019-9850
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52397567");
  # https://www.libreoffice.org/about-us/security/advisories/CVE-2019-9851
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0c1bd6c");
  # https://www.libreoffice.org/about-us/security/advisories/CVE-2019-9852
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6734569");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 6.2.6, 6.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9851");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'LibreOffice Macro Python Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
app_info = vcf::get_app_info(app:'LibreOffice');

constraints = [
  {'min_version':'1.0', 'fixed_version':'6.2.6', 'fixed_display' : 'Upgrade to LibreOffice version 6.2.6 / 6.3.0 or later.'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
