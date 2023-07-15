#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154166);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id(
    "CVE-2021-28129",
    "CVE-2021-33035",
    "CVE-2021-40439",
    "CVE-2021-41830",
    "CVE-2021-41831",
    "CVE-2021-41832"
  );
  script_xref(name:"IAVA", value:"2021-A-0457-S");
  script_xref(name:"IAVA", value:"2022-A-0331-S");

  script_name(english:"Apache OpenOffice < 4.1.11 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"he version of Apache OpenOffice installed on the remote host is a version prior to 4.1.11. It is, therefore, affected
by multiple vulnerabilities :

  - Apache OpenOffice has a dependency on expat software. Versions prior to 2.1.0 were subject to CVE-2013-0340
    a 'Billion Laughs' entity expansion denial of service attack and exploit via crafted XML files. ODF files
    consist of a set of XML files. All versions of Apache OpenOffice up to 4.1.10 are subject to this issue. expat in
    version 4.1.11 is patched. (CVE-2021-40439)

  - While working on Apache OpenOffice 4.1.8 a developer discovered that the DEB package did not install using
    root, but instead used a userid and groupid of 500. This both caused issues with desktop integration and could
    allow a crafted attack on files owned by that user or group if they exist. Users who installed the Apache
    OpenOffice 4.1.8 DEB packaging should upgrade to the latest version of Apache OpenOffice. (CVE-2021-28129)

  - Apache OpenOffice opens dBase/DBF documents and shows the contents as spreadsheets. DBF are database files
    with data organized in fields. When reading DBF data the size of certain fields is not checked: the data
    is just copied into local variables. A carefully crafted document could overflow the allocated space,
    leading to the execution of arbitrary code by altering the contents of the program stack. This issue
    affects Apache OpenOffice up to and including version 4.1.10. (CVE-2021-33035)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2021-28129.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2021-33035.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2021-40439.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2021-41830.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2021-41831.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2021-41832.html");
  # https://cwiki.apache.org/confluence/display/OOOUSERS/AOO+4.1.11+Release+Notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4295487");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache OpenOffice version 4.1.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33035");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:openoffice");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openoffice_installed.nasl");
  script_require_keys("installed_sw/OpenOffice");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::openoffice::get_app_info();
var constraints = [{'fixed_version': '9808', 'fixed_display': '4.1.11 (Build 9808)'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
