#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151300);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/08");

  script_cve_id(
    "CVE-2017-2862",
    "CVE-2017-2870",
    "CVE-2017-6312",
    "CVE-2017-6313",
    "CVE-2017-6314"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : gdk-pixbuf2 (EulerOS-SA-2021-2111)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the gdk-pixbuf2 package installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - gdk-pixbuf is an image loading library that can be
    extended by loadable modules for new image formats. It
    is used by toolkits such as GTK+ or clutter. Security
    Fix(es):The make_available_at_least function in
    io-tiff.c in gdk-pixbuf allows context-dependent
    attackers to cause a denial of service (infinite loop)
    via a large TIFF file.(CVE-2017-6314)Integer underflow
    in the load_resources function in io-icns.c in
    gdk-pixbuf allows context-dependent attackers to cause
    a denial of service (out-of-bounds read and program
    crash) via a crafted image entry size in an ICO
    file.(CVE-2017-6313)An out-of-bounds read flaw was
    found in the way GdkPixbuf handled ICO format files. A
    maliciously crafted ICO file could cause the
    application using GdkPixbuf to crash.(CVE-2017-6312)An
    exploitable integer overflow vulnerability exists in
    the tiff_image_parse functionality of Gdk-Pixbuf 2.36.6
    when compiled with Clang. A specially crafted tiff file
    can cause a heap-overflow resulting in remote code
    execution. An attacker can send a file or a URL to
    trigger this vulnerability.(CVE-2017-2870)An
    exploitable heap overflow vulnerability exists in the
    gdk_pixbuf__jpeg_image_load_increment functionality of
    Gdk-Pixbuf 2.36.6. A specially crafted jpeg file can
    cause a heap overflow resulting in remote code
    execution. An attacker can send a file or url to
    trigger this vulnerability.(CVE-2017-2862)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2111
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?954b4bb0");
  script_set_attribute(attribute:"solution", value:
"Update the affected gdk-pixbuf2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-2870");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gdk-pixbuf2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["gdk-pixbuf2-2.36.5-1.h6"];

foreach (pkg in pkgs)
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdk-pixbuf2");
}
