#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020/11/18. Deprecated by fortios_FG-IR-18-387.nasl

include("compat.inc");

if (description)
{
  script_id(125892);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/24");

  script_cve_id("CVE-2018-13381");
  script_bugtraq_id(104890);

  script_name(english:"Fortinet FortiOS (Mac OS X) <= 5.4, 5.6.x < 5.6.8, 6.0.x < 6.0.5 SSL VPN Buffer Overflow (FG-IR-18-387) (deprecated)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The plugin was deprecated due to checking hosts for FortiClient instead of FortiOS. Use fortios_FG-IR-18-387.nasl
(plugin ID 125886) instead.");
  # https://fortiguard.com/psirt/FG-IR-18-387
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffaddea9");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13381");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient (macOS)", "Host/MacOSX/Version", "Settings/ParanoidReport");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use fortios_FG-IR-18-387.nasl (plugin ID 125886) instead.');
