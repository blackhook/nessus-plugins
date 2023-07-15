#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171199);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2022-41741", "CVE-2022-41742");

  script_name(english:"EulerOS 2.0 SP8 : nginx (EulerOS-SA-2023-1330)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the nginx packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - NGINX Open Source before versions 1.23.2 and 1.22.1, NGINX Open Source Subscription before versions R2 P1
    and R1 P1, and NGINX Plus before versions R27 P1 and R26 P1 have a vulnerability in the module
    ngx_http_mp4_module that might allow a local attacker to corrupt NGINX worker memory, resulting in its
    termination or potential other impact using a specially crafted audio or video file. The issue affects
    only NGINX products that are built with the ngx_http_mp4_module, when the mp4 directive is used in the
    configuration file. Further, the attack is possible only if an attacker can trigger processing of a
    specially crafted audio or video file with the module ngx_http_mp4_module. (CVE-2022-41741)

  - NGINX Open Source before versions 1.23.2 and 1.22.1, NGINX Open Source Subscription before versions R2 P1
    and R1 P1, and NGINX Plus before versions R27 P1 and R26 P1 have a vulnerability in the module
    ngx_http_mp4_module that might allow a local attacker to cause a worker process crash, or might result in
    worker process memory disclosure by using a specially crafted audio or video file. The issue affects only
    NGINX products that are built with the module ngx_http_mp4_module, when the mp4 directive is used in the
    configuration file. Further, the attack is possible only if an attacker can trigger processing of a
    specially crafted audio or video file with the module ngx_http_mp4_module. (CVE-2022-41742)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1330
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7d37250");
  script_set_attribute(attribute:"solution", value:
"Update the affected nginx packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41741");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nginx-all-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nginx-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nginx-mod-http-image-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nginx-mod-http-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nginx-mod-http-xslt-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nginx-mod-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nginx-mod-stream");
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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "nginx-1.12.1-14.h6.eulerosv2r8",
  "nginx-all-modules-1.12.1-14.h6.eulerosv2r8",
  "nginx-filesystem-1.12.1-14.h6.eulerosv2r8",
  "nginx-mod-http-image-filter-1.12.1-14.h6.eulerosv2r8",
  "nginx-mod-http-perl-1.12.1-14.h6.eulerosv2r8",
  "nginx-mod-http-xslt-filter-1.12.1-14.h6.eulerosv2r8",
  "nginx-mod-mail-1.12.1-14.h6.eulerosv2r8",
  "nginx-mod-stream-1.12.1-14.h6.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nginx");
}
