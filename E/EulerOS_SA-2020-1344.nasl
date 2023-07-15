#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135131);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2017-18207", "CVE-2019-9674", "CVE-2020-8492");

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : python2 (EulerOS-SA-2020-1344)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python2 packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - A ZIP bomb attack was found in the Python zipfile
    module. A remote attacker could abuse this flaw by
    providing a specially crafted ZIP file that, when
    decompressed by zipfile, would exhaust system resources
    resulting in a denial of service.(CVE-2019-9674)

  - The Wave_read._read_fmt_chunk function in Lib/wave.py
    in Python through 3.6.4 does not ensure a nonzero
    channel value, which allows attackers to cause a denial
    of service (divide-by-zero and exception) via a crafted
    wav format audio file. NOTE: the vendor disputes this
    issue because Python applications 'need to be prepared
    to handle a wide variety of
    exceptions.'(CVE-2017-18207)

  - Python 2.7 through 2.7.17, 3.5 through 3.5.9, 3.6
    through 3.6.10, 3.7 through 3.7.6, and 3.8 through
    3.8.1 allows an HTTP server to conduct Regular
    Expression Denial of Service (ReDoS) attacks against a
    client because of
    urllib.request.AbstractBasicAuthHandler catastrophic
    backtracking.(CVE-2020-8492)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1344
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66265f32");
  script_set_attribute(attribute:"solution", value:
"Update the affected python2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8492");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-9674");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-unversioned-command");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["python-unversioned-command-2.7.15-10.h21.eulerosv2r8",
        "python2-2.7.15-10.h21.eulerosv2r8",
        "python2-devel-2.7.15-10.h21.eulerosv2r8",
        "python2-libs-2.7.15-10.h21.eulerosv2r8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2");
}
