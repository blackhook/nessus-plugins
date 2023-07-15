#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2021/02/19. Replaced with oracle_access_manager_webgate_cve_2018_11058.nasl.

include('compat.inc');

if (description)
{
  script_id(144089);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2018-11058");

  script_name(english:"Oracle Access Manager (Oct 2020 CPU) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:"This plugin has been deprecated");
  script_set_attribute(attribute:"description", value:
"This plugin is only applicable to the Webgate component of the Access Manager, therefore
it was moved to /nbin/oracle directory with the name oracle_access_manager_webgate_cve_2018_11058.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2020.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11058");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enum_products_win.nbin", "oracle_enum_products_nix.nbin");
  script_require_keys("Oracle/Products/Installed");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use oracle_access_manager_webgate_cve_2018_11058.nasl instead.");

