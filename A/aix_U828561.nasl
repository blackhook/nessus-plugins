#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were extracted
# from AIX Security PTF U828561. The text itself is copyright (C)
# International Business Machines Corp.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(41881);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-2727");

  script_name(english:"AIX 6.1 TL 1 : X11.Dt.ToolTalk (U828561)");
  script_summary(english:"Check for PTF U828561");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is missing AIX PTF U828561, which is related to the
security of the package X11.Dt.ToolTalk.

There is a buffer overflow vulnerability in the ToolTalk library
libtt.a. A remote attacker can exploit this vulnerability when the
rpc.ttdbserver is enabled in /etc/inetd.conf. 

The successful exploitation of this vulnerability allows a remote
attacker to execute arbitrary code as the root user.

The following libraries and executables are vulnerable :

/usr/dt/lib/libtt.a /usr/dt/bin/rpc.ttdbserver."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IZ52849"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate missing security-related fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ToolTalk rpc.ttdbserverd _tt_internal_realpath Buffer Overflow (AIX)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AIX/oslevel", "Host/AIX/version", "Host/AIX/lslpp");

  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("aix.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

if ( aix_check_patch(ml:"610001", patch:"U828561", package:"X11.Dt.ToolTalk.6.1.1.1") < 0 ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");