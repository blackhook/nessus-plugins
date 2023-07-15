#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165888);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/09");

  script_cve_id("CVE-2014-3421", "CVE-2014-3422", "CVE-2014-3424");

  script_name(english:"EulerOS Virtualization 3.0.6.6 : emacs (EulerOS-SA-2022-2494)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the emacs packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - lisp/gnus/gnus-fun.el in GNU Emacs 24.3 and earlier allows local users to overwrite arbitrary files via a
    symlink attack on the /tmp/gnus.face.ppm temporary file. (CVE-2014-3421)

  - lisp/emacs-lisp/find-gc.el in GNU Emacs 24.3 and earlier allows local users to overwrite arbitrary files
    via a symlink attack on a temporary file under /tmp/esrc/. (CVE-2014-3422)

  - lisp/net/tramp-sh.el in GNU Emacs 24.3 and earlier allows local users to overwrite arbitrary files via a
    symlink attack on a /tmp/tramp.##### temporary file. (CVE-2014-3424)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2494
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d499bd9b");
  script_set_attribute(attribute:"solution", value:
"Update the affected emacs packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3424");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-3422");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:emacs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:emacs-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.6");
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
if (uvp != "3.0.6.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "emacs-24.3-21.h7.eulerosv2r7",
  "emacs-common-24.3-21.h7.eulerosv2r7",
  "emacs-filesystem-24.3-21.h7.eulerosv2r7",
  "emacs-nox-24.3-21.h7.eulerosv2r7"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs");
}
