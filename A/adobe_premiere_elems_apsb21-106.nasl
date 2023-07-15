#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154712);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/16");

  script_cve_id(
    "CVE-2021-40785",
    "CVE-2021-40786",
    "CVE-2021-40787",
    "CVE-2021-40788",
    "CVE-2021-40789",
    "CVE-2021-42526",
    "CVE-2021-42527"
  );
  script_xref(name:"IAVA", value:"2021-A-0518-S");

  script_name(english:"Adobe Premiere Elements Multiple Vulnerabilities (APSB21-106)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Adobe Premiere Elements installed on the remote host is prior to 2021 build 19.0 
(20211007.daily.2243969). It is, therefore, affected by multiple vulnerabilities including the following:

  - A NULL pointer de-reference flaw exists in Adobe Premier Elements. An unauthenticated, remote attacker can exploit
    this to cause a denial of service condition when the application attempts to read or write memory with a NULL 
    pointer. (CVE-2021-40785)

  - Multiple arbitrary code execution vulnerabilities exist in Adobe Premier Elements. An unauthenticated, local 
    attacker can exploit these to bypass authentication and execute arbitrary commands. 
    (CVE-2021-40786, CVE-2021-40787, CVE-2021-42526, CVE-2021-42527)

  - Multiple denial of service (DoS) vulnerabilities exist in Adobe Premier Elements. An unauthenticated, local attacker
    can exploit this issue to cause the application to stop responding. (CVE-2021-40788, CVE-2021-40789)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/premiere_elements/apsb21-106.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15e531e8");
  script_set_attribute(attribute:"solution", value:
"Upgrade Adobe Premier Elements to build 19.0 (20211007.daily.2243969)");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42527");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_elements");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_premiere_elements_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Premiere Elements");
  script_require_ports(139, 445);

  exit(0);
}
include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Premiere Elements', win_local:TRUE);

if (
    app_info.version =~ "19\.0" &&
    ( ( ver_compare(ver:app_info['Build timestamp'], fix:'20210809', strict:FALSE) < 0 ) ||
      ( (ver_compare(ver:app_info['Build timestamp'], fix:'20210809', strict:FALSE) == 0) &&
        (ver_compare(ver:app_info['Build level'], fix:'2242976', strict:FALSE) <= 0 )
      )
    )
   )
{
  app_info['display_version'] = app_info['version'] + ' ' + app_info['Build info'];
  vcf::report_results(app_info:app_info, fix:'build 19.0 (20211007.daily.2243969)', severity:SECURITY_HOLE);
}
else
{
  vcf::audit(app_info);
}
