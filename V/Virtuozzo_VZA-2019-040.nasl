#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125308);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_name(english:"Virtuozzo 6 : cpupools / cpupools-features / etc (VZA-2019-040)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the cpupools / cpupools-features / etc
packages installed, the Virtuozzo installation on the remote host is
affected by the following vulnerability :

  - The Microarchitectural Store Buffer Data (MDS) is a
    series of hardware vulnerabilities which allow
    speculative execution attacks on Intel processors. A
    malicious application or guest virtual machine can use
    this flaw to gain access to data stored in internal CPU
    buffers, bypassing security restrictions. For more
    details, visit the Virtuozzo Blog at
    https://www.virtuozzo.com/blog-review/details/blog/view
    /virtuozzo-guidance-on-the-microarchitectural-store-buf
    fer-data-mds-vulnerability.html.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://virtuozzosupport.force.com/s/article/VZA-2019-040");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/mds");
  # https://www.virtuozzo.com/blog-review/details/blog/view/virtuozzo-guidance-on-the-microarchitectural-store-buffer-data-mds-vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?355d0e23");
  script_set_attribute(attribute:"solution", value:
"Update the affected cpupools / cpupools-features / etc package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:cpupools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:cpupools-features");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-reconfiguration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-bios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-bm-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-transporter-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-vi-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-vmm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-vncserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-vzvncserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-virtualization-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-virtualization-sdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-virtualization-sdk-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-parallels-virtualization-sdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 6.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["cpupools-6.0.12-55",
        "cpupools-features-6.0.12-55",
        "parallels-kernel-modules-6.12.26095.1233645-1.el6",
        "parallels-reconfiguration-6.12.26095.1233645-1",
        "parallels-server-6.12.26095.1233645-1.el6",
        "parallels-server-bios-6.12.26095.1233645-1.el6",
        "parallels-server-bm-release-6.0.12-3741",
        "parallels-server-cli-6.12.26095.1233645-1.el6",
        "parallels-server-docs-6.12.26095.1233645-1.el6.el6",
        "parallels-server-efi-6.12.26095.1233645-1.el6",
        "parallels-server-lib-6.12.26095.1233645-1.el6",
        "parallels-server-transporter-agents-6.12.26095.1233645-1.el6",
        "parallels-server-vi-cli-6.12.26095.1233645-1.el6",
        "parallels-server-vmm-6.12.26095.1233645-1.el6",
        "parallels-server-vncserver-6.12.26095.1233645-1.el6",
        "parallels-server-vzvncserver-6.12.26095.1233645-1.el6",
        "parallels-virtualization-sdk-6.12.26095.1233645-1.el6",
        "parallels-virtualization-sdk-devel-6.12.26095.1233645-1.el6",
        "parallels-virtualization-sdk-docs-6.12.26095.1233645-1.el6",
        "parallels-web-6.12.26095.1233645-1",
        "python-parallels-virtualization-sdk-6.12.26095.1233645-1.el6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-6", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpupools / cpupools-features / etc");
}
