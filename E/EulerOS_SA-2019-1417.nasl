#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124920);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-4877",
    "CVE-2016-4971",
    "CVE-2016-7098",
    "CVE-2017-13089",
    "CVE-2017-13090",
    "CVE-2018-0494"
  );
  script_bugtraq_id(
    70751
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : wget (EulerOS-SA-2019-1417)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the wget package installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - A stack-based buffer overflow when processing chunked,
    encoded HTTP responses was found in wget. By tricking
    an unsuspecting user into connecting to a malicious
    HTTP server, an attacker could exploit this flaw to
    potentially execute arbitrary code.(CVE-2017-13089)

  - A flaw was found in the way Wget handled symbolic
    links. A malicious FTP server could allow Wget running
    in the mirror mode (using the '-m' command line option)
    to write an arbitrary file to a location writable to by
    the user running Wget, possibly leading to code
    execution.(CVE-2014-4877)

  - A cookie injection flaw was found in wget. An attacker
    can create a malicious website which, when accessed,
    overrides cookies belonging to arbitrary
    domains.(CVE-2018-0494)

  - It was found that wget used a file name provided by the
    server for the downloaded file when following a HTTP
    redirect to a FTP server resource. This could cause
    wget to create a file with a different name than
    expected, possibly allowing the server to execute
    arbitrary code on the client.(CVE-2016-4971)

  - A heap-based buffer overflow, when processing chunked
    encoded HTTP responses, was found in wget. By tricking
    an unsuspecting user into connecting to a malicious
    HTTP server, an attacker could exploit this flaw to
    potentially execute arbitrary code.(CVE-2017-13090)

  - Race condition in wget 1.17 and earlier, when used in
    recursive or mirroring mode to download a single file,
    might allow remote servers to bypass intended access
    list restrictions by keeping an HTTP connection
    open.(CVE-2016-7098)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1417
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a38e8a1");
  script_set_attribute(attribute:"solution", value:
"Update the affected wget packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13090");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:wget");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["wget-1.14-15.1.h5"];

foreach (pkg in pkgs)
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wget");
}
