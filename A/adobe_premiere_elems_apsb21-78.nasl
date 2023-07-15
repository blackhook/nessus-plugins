#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154230);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/28");

  script_cve_id(
    "CVE-2021-39824",
    "CVE-2021-40700",
    "CVE-2021-40701",
    "CVE-2021-40702",
    "CVE-2021-40703"
  );
  script_xref(name:"IAVA", value:"2021-A-0422-S");

  script_name(english:"Adobe Premiere Elements Multiple Vulnerabilities (APSB21-78)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Adobe Premiere Elements installed on the remote host is prior to 2021 build 19
(20210809.daily.2242976). It is, therefore, affected by multiple arbitrary code execution vulnerabilities due to the
access of memory locations after the end of buffers. An unauthenticated, attacker could exploit these to execute
arbitrary code on an affected system.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/premiere_elements/apsb21-78.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc56e46b");
  script_set_attribute(attribute:"solution", value:
"Upgrade Adobe Premier Elements to build 19.0 (20210809.daily.2242976)");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40703");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_elements");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_premiere_elements_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Premiere Elements");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Premiere Elements', win_local:TRUE);

# Max: 2021 [build 19.0 (20210127.daily.2235820) and earlier]
# Fix: 2021 [build 19.0 (20210809.daily.2242976)]
# Just like AC didn't normalize the version until we see more examples of this product, I'll leave this un vcf-extra'd
if (
    app_info.version =~ "19\.0" &&
    ( ( ver_compare(ver:app_info['Build timestamp'], fix:'20210127', strict:FALSE) < 0 ) ||
      ( (ver_compare(ver:app_info['Build timestamp'], fix:'20210127', strict:FALSE) == 0) &&
        (ver_compare(ver:app_info['Build level'], fix:'2235820', strict:FALSE) <= 0 )
      )
    )
   )
{
  app_info['display_version'] = app_info['version'] + ' ' + app_info['Build info'];
  vcf::report_results(app_info:app_info, fix:'build 19.0 (20210809.daily.2242976)', severity:SECURITY_HOLE);
}
else
{
  vcf::audit(app_info);
}
