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
  script_id(22946);
  script_version("1.36");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2006-3921",
    "CVE-2006-4339",
    "CVE-2006-5201",
    "CVE-2006-7140",
    "CVE-2007-1488",
    "CVE-2007-1526",
    "CVE-2007-4164",
    "CVE-2008-2166",
    "CVE-2008-2518",
    "CVE-2009-1934"
  );
  script_xref(name:"IAVB", value:"2008-B-0045-S");

  script_name(english:"Solaris 10 (sparc) : 116648-25 (deprecated)");
  script_summary(english:"Check for patch 116648-25");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Web Server 6.1: Sun ONE Web Server 6.1 Patch WS61SP13.
Date this patch was last updated by Sun : Sep/20/10

This plugin has been deprecated and either replaced with individual
116648 patch-revision plugins, or deemed non-security related."
  );
  script_set_attribute(attribute:"see_also", value:"https://getupdates.oracle.com/readme/116648-25");
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(79, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/06");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

exit(0, "This plugin has been deprecated. Consult specific patch-revision plugins for patch 116648 instead.");
