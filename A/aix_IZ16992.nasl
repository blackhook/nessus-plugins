#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory kernel_advisory.asc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64316);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2008-1593");

  script_name(english:"AIX 5.2 TL 0 : kernel (IZ16992)");
  script_summary(english:"Check for APAR IZ16992");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"There are multiple vulnerabilities in the AIX kernel :

a) A 64-bit process that is restarted via the checkpoint and restart
feature will gain read and write access to certain areas of kernel
memory, resulting in execution of arbitrary code. Track with the
following APAR numbers: IZ16992, IZ17111, IZ11820, IZ12794. 

b) Remote nodes of a concurrent volume group may crash after
a single node reduces the size of a JFS2 filesystem residing
on the concurrent volume group, resulting in a denial of
service. Track with the following APAR numbers: IZ05246,
IZ04953, IZ04946.

c) The proc filesystem does not enforce directory access
controls correctly when the permission on a directory is
more restrictive than permission on the currently executing
file in that directory, resulting in information leakage.
Track with the following APAR numbers: IZ06022, IZ06663,
IZ06505.

d) Trusted Execution fails to protect files when the
modifications are made via hard links. Affects AIX 6.1 only.
Track with the following APAR number: IZ13418

e) Some WPAR specific system calls may cause undefined
behavior, possibly resulting in a denial of service. Affects
AIX 6.1 only. Track with the following APAR numbers:
IZ13392, IZ13346

f) A user with enough privileges to run ProbeVue can read
from any kernel memory address, resulting in information
leakage. Affects AIX 6.1 only. Track with the following APAR
number: IZ09545

The following files are vulnerable :

/usr/lib/boot/unix_64 /usr/lib/boot/unix_mp
/usr/lib/boot/unix_up /usr/lib/drivers/hd_pin
/usr/sbin/lreducelv

The fixes below include the fixes for all of the above
APARs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/kernel_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8a", package:"bos.mp64", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8a", package:"bos.mp64", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8a", package:"bos.mp64", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8a", package:"bos.mp", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8a", package:"bos.mp", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8a", package:"bos.mp", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8a", package:"bos.rte.lvm", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.88") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8a", package:"bos.rte.lvm", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.99") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8a", package:"bos.rte.lvm", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.106") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8a", package:"bos.up", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8a", package:"bos.up", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8a", package:"bos.up", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8b", package:"bos.mp64", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8b", package:"bos.mp64", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8b", package:"bos.mp64", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8b", package:"bos.mp", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8b", package:"bos.mp", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8b", package:"bos.mp", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8b", package:"bos.rte.lvm", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.88") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8b", package:"bos.rte.lvm", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.99") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8b", package:"bos.rte.lvm", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.106") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8b", package:"bos.up", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8b", package:"bos.up", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8b", package:"bos.up", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8c", package:"bos.mp64", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8c", package:"bos.mp64", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8c", package:"bos.mp64", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8c", package:"bos.mp", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8c", package:"bos.mp", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8c", package:"bos.mp", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8c", package:"bos.rte.lvm", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.88") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8c", package:"bos.rte.lvm", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.99") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8c", package:"bos.rte.lvm", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.106") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8c", package:"bos.up", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8c", package:"bos.up", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8c", package:"bos.up", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8d", package:"bos.mp64", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8d", package:"bos.mp64", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8d", package:"bos.mp64", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8d", package:"bos.mp", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8d", package:"bos.mp", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8d", package:"bos.mp", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8d", package:"bos.rte.lvm", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.88") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8d", package:"bos.rte.lvm", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.99") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8d", package:"bos.rte.lvm", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.106") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8d", package:"bos.up", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8d", package:"bos.up", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_8d", package:"bos.up", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9a", package:"bos.mp64", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9a", package:"bos.mp64", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9a", package:"bos.mp64", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9a", package:"bos.mp", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9a", package:"bos.mp", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9a", package:"bos.mp", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9a", package:"bos.rte.lvm", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.88") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9a", package:"bos.rte.lvm", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.99") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9a", package:"bos.rte.lvm", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.106") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9a", package:"bos.up", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9a", package:"bos.up", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9a", package:"bos.up", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9b", package:"bos.mp64", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9b", package:"bos.mp64", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9b", package:"bos.mp64", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9b", package:"bos.mp", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9b", package:"bos.mp", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9b", package:"bos.mp", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9b", package:"bos.rte.lvm", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.88") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9b", package:"bos.rte.lvm", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.99") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9b", package:"bos.rte.lvm", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.106") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9b", package:"bos.up", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9b", package:"bos.up", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9b", package:"bos.up", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9c", package:"bos.mp64", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9c", package:"bos.mp64", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9c", package:"bos.mp64", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9c", package:"bos.mp", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9c", package:"bos.mp", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9c", package:"bos.mp", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9c", package:"bos.rte.lvm", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.88") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9c", package:"bos.rte.lvm", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.99") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9c", package:"bos.rte.lvm", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.106") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9c", package:"bos.up", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9c", package:"bos.up", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9c", package:"bos.up", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9d", package:"bos.mp64", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9d", package:"bos.mp64", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9d", package:"bos.mp64", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9d", package:"bos.mp", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9d", package:"bos.mp", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9d", package:"bos.mp", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9d", package:"bos.rte.lvm", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.88") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9d", package:"bos.rte.lvm", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.99") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9d", package:"bos.rte.lvm", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.106") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9d", package:"bos.up", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.89") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9d", package:"bos.up", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.102") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ16992_9d", package:"bos.up", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.110") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
