#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136324);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2016-8858",
    "CVE-2016-10009",
    "CVE-2016-10011",
    "CVE-2016-10012"
  );
  script_bugtraq_id(
    93776,
    94968,
    94977,
    94975
  );

  script_name(english:"AIX OpenSSH Advisory : openssh_advisory10.asc");
  script_summary(english:"Checks the version of the OpenSSH packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSH installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote AIX host has a version of OpenSSH installed that is
affected by the following vulnerabilities :

  - OpenSSH is vulnerable to a denial of service, caused by
    an error in the kex_input_kexinit() function. By
    sending specially crafted data during the key exchange
    process, a remote attacker could exploit this
    vulnerability to consume all available memory resources.
    (CVE-2016-8858)

  - OpenSSH could allow a remote authenticated attacker to
    execute arbitrary code on the system, caused by the
    loading of a specially crafted PKCS#11 module across a
    forwarded agent channel. An attacker could exploit this
    vulnerability to write files or execute arbitrary code
    on the system. (CVE-2016-10009)

  - OpenSSH could allow a local authenticated attacker to
    obtain sensitive information, caused by a privilege
    separation flaw. An attacker could exploit this
    vulnerability to obtain host private key material and
    other sensitive information. (CVE-2016-10011)

  - OpenSSH could allow a local attacker to gain elevated
    privileges on the system, caused by improper bounds
    checking in the shared memory manager. An attacker
    could exploit this vulnerability to gain elevated
    privileges on the system. (CVE-2016-10012)");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/openssh_advisory10.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10012");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/05");
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

ifixes_6203 = "(6203_ifix)";

if (aix_check_ifix(release:"5.3", patch:ifixes_6203, package:"openssh.base.client", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6203") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:ifixes_6203, package:"openssh.base.client", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6203") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_6203, package:"openssh.base.client", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6203") < 0) flag++;
if (aix_check_ifix(release:"7.2", patch:ifixes_6203, package:"openssh.base.client", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6203") < 0) flag++;

if (aix_check_ifix(release:"5.3", patch:ifixes_6203, package:"openssh.base.server", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6203") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:ifixes_6203, package:"openssh.base.server", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6203") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_6203, package:"openssh.base.server", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6203") < 0) flag++;
if (aix_check_ifix(release:"7.2", patch:ifixes_6203, package:"openssh.base.server", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6203") < 0) flag++;

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : aix_report_extra
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh.base.client / openssh.base.server");
}
