#%NASL_MIN_LEVEL 70300
##
#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020/05/11. Deprecated by macosx_adobe_creative_cloud_apsb21-76.nasl.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153458);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2021-28613");
  script_xref(name:"IAVA", value:"2021-A-0421-S");

  script_name(english:"Adobe Creative Cloud Desktop Application <= 5.4 Arbitrary File System Write (APSB21-76) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud Desktop Application installed on the remote Windows host is prior or equal to 5.4. 
It is, therefore, affected by an arbitrary file system write vulnerability. Creation of a temporary file in a directory 
with incorrect permissions allows an authenticated, local attacker to execute arbitrary code.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated, as the APSB21-76 advisory does not have Windows as an affected version. Use
macosx_adobe_creative_cloud_apsb21-76.nasl (plugin ID 153459) instead.");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb21-76.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d345a92d");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28613");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_creative_cloud_installed.nbin");
  script_require_keys("installed_sw/Adobe Creative Cloud");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use macosx_adobe_creative_cloud_apsb21-76.nasl (plugin ID 153459) instead.');
