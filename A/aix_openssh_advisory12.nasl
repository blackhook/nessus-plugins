#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136325);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2018-15473");
  script_bugtraq_id(105140);

  script_name(english:"AIX OpenSSH Advisory : openssh_advisory12.asc");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSH installed that is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote AIX host has a version of OpenSSH installed that is
affected by a vulnerability that allows a remote attacker to obtain
sensitive information, caused by different responses to valid and
invalid authentication attempts. By sending a specially crafted
request, an attacker could exploit this vulnerability to enumerate
valid usernames.");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/openssh_advisory12.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15473");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include('aix.inc');
include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item("Host/AIX/version");
if (isnull(oslevel)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
if ( oslevel != "AIX-5.3" && oslevel != "AIX-6.1" && oslevel != "AIX-7.1" && oslevel != "AIX-7.2" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.3 / 6.1 / 7.1 / 7.2", oslevel);
}

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

ifixes = "(15473_fix)";


if (aix_check_ifix(release:"5.3", patch:ifixes, package:"openssh.base.client", minfilesetver:"4.0.0.5200", maxfilesetver:"7.5.102.1500") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:ifixes, package:"openssh.base.client", minfilesetver:"4.0.0.5200", maxfilesetver:"7.5.102.1500") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes, package:"openssh.base.client", minfilesetver:"4.0.0.5200", maxfilesetver:"7.5.102.1500") < 0) flag++;
if (aix_check_ifix(release:"7.2", patch:ifixes, package:"openssh.base.client", minfilesetver:"4.0.0.5200", maxfilesetver:"7.5.102.1500") < 0) flag++;

if (aix_check_ifix(release:"5.3", patch:ifixes, package:"openssh.base.server", minfilesetver:"4.0.0.5200", maxfilesetver:"7.5.102.1500") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:ifixes, package:"openssh.base.server", minfilesetver:"4.0.0.5200", maxfilesetver:"7.5.102.1500") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes, package:"openssh.base.server", minfilesetver:"4.0.0.5200", maxfilesetver:"7.5.102.1500") < 0) flag++;
if (aix_check_ifix(release:"7.2", patch:ifixes, package:"openssh.base.server", minfilesetver:"4.0.0.5200", maxfilesetver:"7.5.102.1500") < 0) flag++;

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : aix_report_extra
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh.base.client / openssh.base.server");
}
