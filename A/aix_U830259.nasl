#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were extracted
# from AIX Security PTF U830259. The text itself is copyright (C)
# International Business Machines Corp.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46406);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-1039");
  script_bugtraq_id(40248);
  script_xref(name:"IAVA", value:"2010-A-0073-S");

  script_name(english:"AIX 5.3 TL 9 : bos.net.nfs.client (U830259)");
  script_summary(english:"Check for PTF U830259");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is missing AIX PTF U830259, which is related to the
security of the package bos.net.nfs.client.

An integer overflow vulnerability was reported in the rpc.pcnfsd
service within the several systems. The rpc.pcnfsd daemon handles
requests from PC-NFS clients for authentication services on remote
machines. These services include authentication for mounting and for
print spooling. The vulnerability is triggered when parsing crafted
RPC requests. A remote attacker can leverage this vulnerability by
sending a crafted RPC message to the target host, to potentially
inject and execute arbitrary code.
"
  );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IZ73874");
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate missing security-related fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-1039");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/19");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( aix_check_patch(ml:"530009", patch:"U830259", package:"bos.net.nfs.client.5.3.9.6") < 0 ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
