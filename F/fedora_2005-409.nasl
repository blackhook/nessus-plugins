#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
#
# This script has been deprecated as the associated advisory is not
# security-related.
#
# Disabled on 2012/09/30.
#

#
# (C) Tenable Network Security, Inc.
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(18576);
 script_version ("1.8");
 
 name["english"] = "Fedora Core 4 2005-409: elinks";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-409 (elinks).

Links is a text-based Web browser. Links does not display any images,
but it does support frames, tables and most other HTML tags. Links'
advantage over graphical browsers is its speed--Links starts and exits
quickly and swiftly displays Web pages.


* Sat Jun 11 2005 Karel Zak <kzak redhat com> 0.10.3-3.1

- fix #159575 - elinks fails to render entire page" );
 script_set_attribute(attribute:"solution", value:
"http://www.redhat.com/archives/fedora-announce-list/2005-June/msg00013.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/28");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the elinks package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2018 Tenable Network Security, Inc.");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

# Deprecated.
exit(0, "The associated advisory is not security-related.");


include("rpm.inc");
if ( rpm_check( reference:"elinks-0.10.3-3.1", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
