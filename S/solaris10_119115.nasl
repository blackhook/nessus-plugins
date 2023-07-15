#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2018/03/12. Deprecated and either replaced by
# individual patch-revision plugins, or has been deemed a
# non-security advisory.
#
include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22954);
  script_version("1.44");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0293", "CVE-2006-0294", "CVE-2006-0295", "CVE-2006-0296", "CVE-2006-0297", "CVE-2006-0298", "CVE-2006-0299", "CVE-2006-0748", "CVE-2006-0749", "CVE-2006-0884", "CVE-2006-1529", "CVE-2006-1530", "CVE-2006-1531", "CVE-2006-1723", "CVE-2006-1724", "CVE-2006-1725", "CVE-2006-1726", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1736", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-3805", "CVE-2006-5463", "CVE-2006-6498", "CVE-2006-6499", "CVE-2007-1794");

  script_name(english:"Solaris 10 (sparc) : 119115-36 (deprecated)");
  script_summary(english:"Check for patch 119115-36");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Mozilla 1.7 patch.
Date this patch was last updated by Sun : Sep/13/14

This plugin has been deprecated and either replaced with individual
119115 patch-revision plugins, or deemed non-security related."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/119115-36"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox location.QueryInterface() Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 79, 94, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

exit(0, "This plugin has been deprecated. Consult specific patch-revision plugins for patch 119115 instead.");
