##
#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2021/10/26. Deprecated Due to Age and likelihood of false positives.
##

include("compat.inc");

if (description)
{
  script_id(12203);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/28");

  script_cve_id("CVE-2004-1920");
  script_bugtraq_id(10095);

  script_name(english:"Web Application Default Username ('super'/'1502') / Password ('super'/'1502') - deprecated");
  script_summary(english:"Attempts to login to a default account");

  script_set_attribute(attribute:"synopsis", value:"This plugin has been deprecated");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated due to age and the likelihood of false positives.");

  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2004/Apr/214");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);

  exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated due to age and the likelihood of false positives.");
