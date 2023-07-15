#%NASL_MIN_LEVEL 70300

# @DEPRECATED@
#
# This script has been deprecated as the associated patch is has
# been withdrawn.
#
# Disabled on 2014/02/12.
#

#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);
include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(72165);
 script_version("1.8");

 script_name(english: "Solaris 10 (sparc) : 150400-06");
script_cve_id("CVE-2013-5876");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 150400-06");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: Kernel Patch.
Date this patch was last updated by Sun : Dec/13/13');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://blogs.oracle.com/patch/entry/heads_up_regression_in_solaris");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
 script_set_attribute(attribute: "patch_publication_date", value: "2013/12/13");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 script_summary(english: "Check for patch 150400-06");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2014-2021 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch has been withdrawn.");
