##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161582);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/26");

  script_cve_id("CVE-2021-23222");

  script_name(english:"EulerOS 2.0 SP3 : postgresql (EulerOS-SA-2022-1756)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the postgresql packages installed, the EulerOS installation on the remote host is affected
by the following vulnerabilities :

  - A man-in-the-middle attacker can inject false responses to the client's first few queries, despite the use
    of SSL certificate verification and encryption. (CVE-2021-23222)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1756
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24848209");
  script_set_attribute(attribute:"solution", value:
"Update the affected postgresql packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23222");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "postgresql-9.2.24-1.h5",
  "postgresql-contrib-9.2.24-1.h5",
  "postgresql-devel-9.2.24-1.h5",
  "postgresql-docs-9.2.24-1.h5",
  "postgresql-libs-9.2.24-1.h5",
  "postgresql-plperl-9.2.24-1.h5",
  "postgresql-plpython-9.2.24-1.h5",
  "postgresql-pltcl-9.2.24-1.h5",
  "postgresql-server-9.2.24-1.h5",
  "postgresql-test-9.2.24-1.h5"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql");
}