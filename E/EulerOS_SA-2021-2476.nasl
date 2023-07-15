#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153608);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/28");

  script_cve_id("CVE-2017-20005", "CVE-2021-3618");

  script_name(english:"EulerOS 2.0 SP8 : nginx (EulerOS-SA-2021-2476)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the nginx packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - NGINX before 1.13.6 has a buffer overflow for years that exceed four digits, as demonstrated by a file
    with a modification date in 1969 that causes an integer overflow (or a false modification date far in the
    future), when encountered by the autoindex module. (CVE-2017-20005)

  - ALPACA is an application layer protocol content confusion attack, exploiting TLS servers implementing
    different protocols but using compatible certificates, such as multi-domain or wildcard certificates. A
    MiTM attacker having access to victim's traffic at the TCP/IP layer can redirect traffic from one
    subdomain to another, resulting in a valid TLS session. This breaks the authentication of TLS and cross-
    protocol attacks may be possible where the behavior of one protocol service may compromise the other at
    the application layer. (CVE-2021-3618)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2476
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e412bd4");
  script_set_attribute(attribute:"solution", value:
"Update the affected nginx packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-20005");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/24");

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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "nginx-1.12.1-14.h5.eulerosv2r8",
  "nginx-all-modules-1.12.1-14.h5.eulerosv2r8",
  "nginx-filesystem-1.12.1-14.h5.eulerosv2r8",
  "nginx-mod-http-image-filter-1.12.1-14.h5.eulerosv2r8",
  "nginx-mod-http-perl-1.12.1-14.h5.eulerosv2r8",
  "nginx-mod-http-xslt-filter-1.12.1-14.h5.eulerosv2r8",
  "nginx-mod-mail-1.12.1-14.h5.eulerosv2r8",
  "nginx-mod-stream-1.12.1-14.h5.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nginx");
}
