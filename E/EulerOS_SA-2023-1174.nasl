#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169821);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id("CVE-2021-35937", "CVE-2021-35938", "CVE-2021-35939");

  script_name(english:"EulerOS Virtualization 2.10.0 : rpm (EulerOS-SA-2023-1174)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the rpm packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - A race condition vulnerability was found in rpm. A local unprivileged user could use this flaw to bypass
    the checks that were introduced in response to CVE-2017-7500 and CVE-2017-7501, potentially gaining root
    privileges. The highest threat from this vulnerability is to data confidentiality and integrity as well as
    system availability. (CVE-2021-35937)

  - A symbolic link issue was found in rpm. It occurs when rpm sets the desired permissions and credentials
    after installing a file. A local unprivileged user could use this flaw to exchange the original file with
    a symbolic link to a security-critical file and escalate their privileges on the system. The highest
    threat from this vulnerability is to data confidentiality and integrity as well as system availability.
    (CVE-2021-35938)

  - It was found that the fix for CVE-2017-7500 and CVE-2017-7501 was incomplete: the check was only
    implemented for the parent directory of the file to be created. A local unprivileged user who owns another
    ancestor directory could potentially use this flaw to gain root privileges. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability. (CVE-2021-35939)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1174
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c35356ff");
  script_set_attribute(attribute:"solution", value:
"Update the affected rpm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35939");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-plugin-systemd-inhibit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.10.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.10.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "python3-rpm-4.15.1-17.h42.eulerosv2r10",
  "rpm-4.15.1-17.h42.eulerosv2r10",
  "rpm-libs-4.15.1-17.h42.eulerosv2r10",
  "rpm-plugin-systemd-inhibit-4.15.1-17.h42.eulerosv2r10"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rpm");
}
