#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020/11/18. Deprecated by fortios_FG-IR-17-242.nasl

include("compat.inc");

if (description)
{
  script_id(125890);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/24");

  script_cve_id("CVE-2017-14186");
  script_bugtraq_id(101955);

  script_name(english:"Fortinet FortiOS (Mac OS X) <= 5.4 / 5.6.x < 5.6.8 / 6.0.x < 6.0.5 SSL VPN Web Portal login redir XSS (FG-IR-17-242) (deprecated)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The plugin was deprecated due to checking hosts for FortiClient instead of FortiOS. Use fortios_FG-IR-17-242.nasl
(plugin ID 104886) instead.");
  # https://fortiguard.com/psirt/FG-IR-17-242
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3c15f32");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14186");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/27");
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

exit(0, 'This plugin has been deprecated. Use fortios_FG-IR-17-242.nasl (plugin ID 104886) instead.');
