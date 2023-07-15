#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165925);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_cve_id("CVE-2022-0563");

  script_name(english:"EulerOS Virtualization 3.0.6.0 : util-linux (EulerOS-SA-2022-2593)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the util-linux packages installed, the EulerOS Virtualization installation on the remote
host is affected by the following vulnerabilities :

  - A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The
    Readline library uses an 'INPUTRC' environment variable to get a path to the library config file. When the
    library cannot parse the specified file, it prints an error message containing data from the file. This
    flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation.
    This flaw affects util-linux versions prior to 2.37.4. (CVE-2022-0563)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2593
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e68a7c00");
  script_set_attribute(attribute:"solution", value:
"Update the affected util-linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0563");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libblkid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libfdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libfdisk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsmartcols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsmartcols-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libuuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:util-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:uuidd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

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
  "libblkid-2.32.1-1.h15.eulerosv2r8",
  "libblkid-devel-2.32.1-1.h15.eulerosv2r8",
  "libfdisk-2.32.1-1.h15.eulerosv2r8",
  "libfdisk-devel-2.32.1-1.h15.eulerosv2r8",
  "libmount-2.32.1-1.h15.eulerosv2r8",
  "libsmartcols-2.32.1-1.h15.eulerosv2r8",
  "libsmartcols-devel-2.32.1-1.h15.eulerosv2r8",
  "libuuid-2.32.1-1.h15.eulerosv2r8",
  "libuuid-devel-2.32.1-1.h15.eulerosv2r8",
  "util-linux-2.32.1-1.h15.eulerosv2r8",
  "util-linux-user-2.32.1-1.h15.eulerosv2r8",
  "uuidd-2.32.1-1.h15.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "util-linux");
}