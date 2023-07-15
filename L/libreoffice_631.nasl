#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129535);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/16");

  script_cve_id("CVE-2019-9854", "CVE-2019-9855");
  script_xref(name:"IAVB", value:"2019-B-0078-S");

  script_name(english:"LibreOffice < 6.2.7 / 6.3.x < 6.3.1 Multiple Vulnerabilities (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of LibreOffice installed on the remote Windows host is prior to 6.2.7 or 6.3.x prior to 6.3.1. It is,
therefore, affected by the following vulnerabilities:

  - A directory traversal vulnerability resulting from a feature in LibreOffice which allows documents to
    specify pre-installed macros that can be executed on various script events. Only scripts under the
    'share/Scripts/python' and /user/Scripts/python' sub-directories of the LibreOffice install should be
    accessible. Previous protection to address CVE-2019-9852 to avoid a similar attack was added, however this
    protection can be bypassed due to a flaw in how LibreOffice assembles the final script URL location. This
    flaw can be exploited to allow scripts in arbitrary locations on the file system to be executed. 
    (CVE-2019-9854)

  - An arbitrary script execution vulnerability caused by a flaw allowing event-based execution of Python
    scripts within a document. Previous protection was added to address this flaw, however due to a Windows
    8.3 path equivalence flaw, Windows systems are still vulnerable via Windows filename pseudonyms. Note,
    LibreLogo must be installed for this vulnerability to be exploitable, however LibreLogo is frequently
    bundled with LibreOffice. (CVE-2019-9855)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.libreoffice.org/about-us/security/advisories/cve-2019-9854/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43a121e2");
  # https://www.libreoffice.org/about-us/security/advisories/cve-2019-9855/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c323d2ce");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 6.2.7, 6.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9854");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
app_info = vcf::get_app_info(app:'LibreOffice');

constraints = [
  {'fixed_version':'6.2.7'},
  {'min_version':'6.3', 'fixed_version':'6.3.1'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
