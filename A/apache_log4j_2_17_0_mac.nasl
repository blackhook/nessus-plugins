#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020/12/19. Deprecated by apache_log4j_2_17_0.nasl.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156184);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/21");

  script_cve_id("CVE-2021-45105");
  
  script_xref(name:"IAVA", value:"2021-A-0573");

  script_name(english:"Apache Log4j 2.x < 2.17.0 DoS (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as a duplicated of apache_log4j_2_17_0.nasl (156183).");

  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-p6xc-xr62-6r2g");  
  script_set_attribute(attribute:"see_also", value:"https://logging.apache.org/log4j/2.x/security.html");  

  script_set_attribute(attribute:"solution", value:
"n/a.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45105");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:log4j");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_log4j_nix_installed.nbin", "ssh_get_info.nasl");
  script_require_keys("installed_sw/Apache Log4j", "Host/MacOSX/Version");

  exit(0);
}

exit(0, 'This plugin has been deprecated as a duplicated of apache_log4j_2_17_0.nasl (156183). Use 156183 instead');