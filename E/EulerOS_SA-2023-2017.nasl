#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176585);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/02");

  script_cve_id("CVE-2023-0687");

  script_name(english:"EulerOS Virtualization 2.9.0 : glibc (EulerOS-SA-2023-2017)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glibc packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - ** DISPUTED ** A vulnerability was found in GNU C Library 2.38. It has been declared as critical. This
    vulnerability affects the function __monstartup of the file gmon.c of the component Call Graph Monitor.
    The manipulation leads to buffer overflow. It is recommended to apply a patch to fix this issue.
    VDB-220246 is the identifier assigned to this vulnerability. NOTE: The real existence of this
    vulnerability is still doubted at the moment. The inputs that induce this vulnerability are basically
    addresses of the running application that is built with gmon enabled. It's basically trusted input or
    input that needs an actual security flaw to be compromised or controlled. (CVE-2023-0687)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3705de1d");
  script_set_attribute(attribute:"solution", value:
"Update the affected glibc packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0687");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-all-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-debugutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-locale-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libnsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.0");
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
if (uvp != "2.9.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "glibc-2.28-61.h43.eulerosv2r9",
  "glibc-all-langpacks-2.28-61.h43.eulerosv2r9",
  "glibc-common-2.28-61.h43.eulerosv2r9",
  "glibc-debugutils-2.28-61.h43.eulerosv2r9",
  "glibc-locale-source-2.28-61.h43.eulerosv2r9",
  "libnsl-2.28-61.h43.eulerosv2r9",
  "nscd-2.28-61.h43.eulerosv2r9"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
