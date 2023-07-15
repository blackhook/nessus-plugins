#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-306b84fd07.
#

include("compat.inc");

if (description)
{
  script_id(141270);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-25595", "CVE-2020-25596", "CVE-2020-25597", "CVE-2020-25598", "CVE-2020-25599", "CVE-2020-25600", "CVE-2020-25601", "CVE-2020-25602", "CVE-2020-25603", "CVE-2020-25604");
  script_xref(name:"FEDORA", value:"2020-306b84fd07");

  script_name(english:"Fedora 33 : xen (2020-306b84fd07)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"x86 pv: Crash when handling guest access to MSR_MISC_ENABLE [XSA-333,
CVE-2020-25602] (#1881619) Missing unlock in XENMEM_acquire_resource
error path [XSA-334, CVE-2020-25598] (#1881616) race when migrating
timers between x86 HVM vCPU-s [XSA-336, CVE-2020-25604] (#1881618) PCI
passthrough code reading back hardware registers [XSA-337,
CVE-2020-25595] (#1881587) once valid event channels may not turn
invalid [XSA-338, CVE-2020-25597] (#1881588) x86 pv guest kernel DoS
via SYSENTER [XSA-339, CVE-2020-25596] (#1881617) Missing memory
barriers when accessing/allocating an event channel [XSA-340,
CVE-2020-25603] (#1881583) out of bounds event channels available to
32-bit x86 domains [XSA-342, CVE-2020-25600] (#1881582) races with
evtchn_reset() [XSA-343, CVE-2020-25599] (#1881581) lack of preemption
in evtchn_reset() / evtchn_destroy() [XSA-344, CVE-2020-25601]
(#1881586)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-306b84fd07"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25597");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:33");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^33([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 33", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC33", reference:"xen-4.14.0-5.fc33")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
