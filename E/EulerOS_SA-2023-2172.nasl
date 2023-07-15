#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177040);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/09");

  script_cve_id("CVE-2022-4254");

  script_name(english:"EulerOS 2.0 SP5 : sssd (EulerOS-SA-2023-2172)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the sssd packages installed, the EulerOS installation on the remote host is affected by the
following vulnerabilities :

  - sssd: libsss_certmap fails to sanitise certificate data used in LDAP filters (CVE-2022-4254)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2172
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec003750");
  script_set_attribute(attribute:"solution", value:
"Update the affected sssd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4254");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_certmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "libipa_hbac-1.16.0-19.5.h9.eulerosv2r7",
  "libsss_autofs-1.16.0-19.5.h9.eulerosv2r7",
  "libsss_certmap-1.16.0-19.5.h9.eulerosv2r7",
  "libsss_idmap-1.16.0-19.5.h9.eulerosv2r7",
  "libsss_nss_idmap-1.16.0-19.5.h9.eulerosv2r7",
  "libsss_simpleifp-1.16.0-19.5.h9.eulerosv2r7",
  "libsss_sudo-1.16.0-19.5.h9.eulerosv2r7",
  "python-libipa_hbac-1.16.0-19.5.h9.eulerosv2r7",
  "python-libsss_nss_idmap-1.16.0-19.5.h9.eulerosv2r7",
  "python-sss-1.16.0-19.5.h9.eulerosv2r7",
  "python-sss-murmur-1.16.0-19.5.h9.eulerosv2r7",
  "python-sssdconfig-1.16.0-19.5.h9.eulerosv2r7",
  "sssd-1.16.0-19.5.h9.eulerosv2r7",
  "sssd-ad-1.16.0-19.5.h9.eulerosv2r7",
  "sssd-client-1.16.0-19.5.h9.eulerosv2r7",
  "sssd-common-1.16.0-19.5.h9.eulerosv2r7",
  "sssd-common-pac-1.16.0-19.5.h9.eulerosv2r7",
  "sssd-dbus-1.16.0-19.5.h9.eulerosv2r7",
  "sssd-ipa-1.16.0-19.5.h9.eulerosv2r7",
  "sssd-krb5-1.16.0-19.5.h9.eulerosv2r7",
  "sssd-krb5-common-1.16.0-19.5.h9.eulerosv2r7",
  "sssd-ldap-1.16.0-19.5.h9.eulerosv2r7",
  "sssd-libwbclient-1.16.0-19.5.h9.eulerosv2r7",
  "sssd-proxy-1.16.0-19.5.h9.eulerosv2r7",
  "sssd-tools-1.16.0-19.5.h9.eulerosv2r7"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sssd");
}
