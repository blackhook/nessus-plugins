#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66293);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/10");

  script_xref(name:"IAVA", value:"0001-A-0648");

  script_name(english:"Unix Operating System on Extended Support");
  script_summary(english:"Checks if operating system is on extended support");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running an operating system that is on extended
support."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the remote host uses a Unix or Unix-like
operating system that has transitioned to an extended portion in its
support life cycle. Continued access to new security updates requires
payment of an additional fee and / or configuration changes to the
package management tool.  Without that, the host likely will be
missing security updates."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Ensure that the host subscribes to the vendor's extended support
plan and continues to receive security updates."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"General");

  script_dependencies("unsupported_operating_system.nasl");
  script_require_keys("Host/OS/extended_support");

  exit(0);
}


include('global_settings.inc');
include('misc_func.inc');


var kb = get_kb_item_or_exit('Host/OS/extended_support');
security_report_v4(port:0, extra:kb, severity:SECURITY_NOTE);
