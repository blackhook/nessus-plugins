#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99856);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-9445",
    "CVE-2016-9447",
    "CVE-2016-9809"
  );

  script_name(english:"EulerOS 2.0 SP1 : gstreamer-plugins-bad-free (EulerOS-SA-2017-1010)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the gstreamer-plugins-bad-free packages
installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - An integer overflow flaw, leading to a heap-based
    buffer overflow, was found in GStreamer's VMware VMnc
    video file format decoding plug-in. A remote attacker
    could use this flaw to cause an application using
    GStreamer to crash or, potentially, execute arbitrary
    code with the privileges of the user running the
    application. (CVE-2016-9445)

  - A memory corruption flaw was found in GStreamer's
    Nintendo NSF music file format decoding plug-in. A
    remote attacker could use this flaw to cause an
    application using GStreamer to crash or, potentially,
    execute arbitrary code with the privileges of the user
    running the application. (CVE-2016-9447)

  - An out-of-bounds heap read flaw was found in
    GStreamer's H.264 parser. A remote attacker could use
    this flaw to cause an application using GStreamer to
    crash. (CVE-2016-9809)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e858936");
  script_set_attribute(attribute:"solution", value:
"Update the affected gstreamer-plugins-bad-free packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gstreamer-plugins-bad-free");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gstreamer-plugins-bad-free-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gstreamer-plugins-bad-free-devel-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["gstreamer-plugins-bad-free-0.10.23-22",
        "gstreamer-plugins-bad-free-devel-0.10.23-22",
        "gstreamer-plugins-bad-free-devel-docs-0.10.23-22"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-plugins-bad-free");
}
