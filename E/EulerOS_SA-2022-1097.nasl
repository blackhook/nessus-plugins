#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157976);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/12");

  script_cve_id("CVE-2021-3621");

  script_name(english:"EulerOS Virtualization 3.0.6.0 : sssd (EulerOS-SA-2022-1097)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the sssd packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - A flaw was found in SSSD, where the sssctl command was vulnerable to shell command injection via the logs-
    fetch and cache-expire subcommands. This flaw allows an attacker to trick the root user into running a
    specially crafted sssctl command, such as via sudo, to gain root access. The highest threat from this
    vulnerability is to confidentiality, integrity, as well as system availability. (CVE-2021-3621)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1097
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8cd23ca");
  script_set_attribute(attribute:"solution", value:
"Update the affected sssd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3621");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_certmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-nfs-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-winbind-idmap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "libipa_hbac-2.0.0-3.h42.eulerosv2r8",
  "libsss_autofs-2.0.0-3.h42.eulerosv2r8",
  "libsss_certmap-2.0.0-3.h42.eulerosv2r8",
  "libsss_idmap-2.0.0-3.h42.eulerosv2r8",
  "libsss_nss_idmap-2.0.0-3.h42.eulerosv2r8",
  "libsss_simpleifp-2.0.0-3.h42.eulerosv2r8",
  "libsss_sudo-2.0.0-3.h42.eulerosv2r8",
  "python2-libipa_hbac-2.0.0-3.h42.eulerosv2r8",
  "python2-libsss_nss_idmap-2.0.0-3.h42.eulerosv2r8",
  "python2-sss-2.0.0-3.h42.eulerosv2r8",
  "python2-sss-murmur-2.0.0-3.h42.eulerosv2r8",
  "python2-sssdconfig-2.0.0-3.h42.eulerosv2r8",
  "python3-libipa_hbac-2.0.0-3.h42.eulerosv2r8",
  "python3-libsss_nss_idmap-2.0.0-3.h42.eulerosv2r8",
  "python3-sss-2.0.0-3.h42.eulerosv2r8",
  "python3-sss-murmur-2.0.0-3.h42.eulerosv2r8",
  "python3-sssdconfig-2.0.0-3.h42.eulerosv2r8",
  "sssd-2.0.0-3.h42.eulerosv2r8",
  "sssd-ad-2.0.0-3.h42.eulerosv2r8",
  "sssd-client-2.0.0-3.h42.eulerosv2r8",
  "sssd-common-2.0.0-3.h42.eulerosv2r8",
  "sssd-common-pac-2.0.0-3.h42.eulerosv2r8",
  "sssd-dbus-2.0.0-3.h42.eulerosv2r8",
  "sssd-ipa-2.0.0-3.h42.eulerosv2r8",
  "sssd-kcm-2.0.0-3.h42.eulerosv2r8",
  "sssd-krb5-2.0.0-3.h42.eulerosv2r8",
  "sssd-krb5-common-2.0.0-3.h42.eulerosv2r8",
  "sssd-ldap-2.0.0-3.h42.eulerosv2r8",
  "sssd-libwbclient-2.0.0-3.h42.eulerosv2r8",
  "sssd-nfs-idmap-2.0.0-3.h42.eulerosv2r8",
  "sssd-proxy-2.0.0-3.h42.eulerosv2r8",
  "sssd-tools-2.0.0-3.h42.eulerosv2r8",
  "sssd-winbind-idmap-2.0.0-3.h42.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
