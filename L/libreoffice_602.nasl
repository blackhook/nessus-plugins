#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122586);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2018-10120");

  script_name(english:"LibreOffice < 5.4.6 and < 6.0.2 Heap Buffer Overflow");
  script_summary(english:"Checks the version of LibreOffice.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host may allow attackers to
cause a denial of service or possibly have other unspecified impact.");
  script_set_attribute(attribute:"description", value:
"The LibreOffice installed on the remote host is either 5.x prior to
5.4.6 or 6.x prior to 6.0.2. A heap-based buffer overflow condition
exists in The SwCTBWrapper::Read function due to improperly checking
the bounds of the index into the dynamically allocated buffer. An
unauthenticated, remote attacker can exploit this, via a specifically
crafted word document opened by user to cause a denial of service
condition or the execution of arbitrary code.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.libreoffice.org/about-us/security/advisories/cve-2018-10120/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87aeb0f9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version to 5.4.6, 6.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10120");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
app_info = vcf::get_app_info(app:"LibreOffice");

constraints = [
  {"fixed_version":"5.4.6.0"},
  {"min_version":"6.0","fixed_version":"6.0.2.0"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
