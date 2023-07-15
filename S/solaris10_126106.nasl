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
  script_id(26990);
  script_version("1.37");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-2267", "CVE-2009-3433");
  script_bugtraq_id(36486);
  script_xref(name:"IAVA", value:"2009-A-0087-S");

  script_name(english:"Solaris 10 (sparc) : 126106-42 (deprecated)");
  script_summary(english:"Check for patch 126106-42");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Sun Cluster 3.2: CORE patch for Solaris 10.
Date this patch was last updated by Sun : Apr/27/10

This plugin has been deprecated and either replaced with individual
126106 patch-revision plugins, or deemed non-security related."
  );
  script_set_attribute(attribute:"see_also", value:"https://getupdates.oracle.com/readme/126106-42");
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/12");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

exit(0, "This plugin has been deprecated. Consult specific patch-revision plugins for patch 126106 instead.");
