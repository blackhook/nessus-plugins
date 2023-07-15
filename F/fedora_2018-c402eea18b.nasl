#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-c402eea18b.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120769);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-15686", "CVE-2018-15687", "CVE-2018-15688");
  script_xref(name:"FEDORA", value:"2018-c402eea18b");

  script_name(english:"Fedora 29 : systemd (2018-c402eea18b)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fix a local vulnerability from a race condition in
    chown-recursive (CVE-2018-15687, #1639076)

  - Fix a local vulnerability from invalid handling of long
    lines in state deserialization (CVE-2018-15686,
    #1639071)

  - Fix a remote vulnerability in DHCPv6 in systemd-networkd
    (CVE-2018-15688, #1639067)

  - The DHCP server is started only when link is UP

  - DHCPv6 prefix delegation is improved

  - Downgrade logging of various messages and add loging in
    other places

  - Many many fixes in error handling and minor memory leaks
    and such

  - Fix typos and omissions in documentation

  - Typo in %%_environmnentdir rpm macro is fixed (with
    backwards compatibility preserved)

  - Matching by MACAddress= in systemd-networkd is fixed

  - Creation of user runtime directories is improved, and
    the user manager is only stopped after 10 s after the
    user logs out (#1642460 and other bugs)

  - systemd units systemd-timesyncd, systemd-resolved,
    systemd-networkd are switched back to use DynamicUser=0

  - Aliases are now resolved when loading modules from pid1.
    This is a (redundant) fix for a brief kernel regression.

  - 'systemctl --wait start' exits immediately if no valid
    units are named

  - zram devices are not considered as candidates for
    hibernation

  - ECN is not requested for both in- and out-going
    connections (the sysctl overide for net.ipv4.tcp_ecn is
    removed)

  - Various smaller improvements to unit ordering and
    dependencies

  - generators are now called with the manager's environment

  - Handling of invalid (intentionally corrupt) dbus
    messages is improved, fixing potential local DOS avenues

  - The target of symlinks links in .wants/ and .requires/
    is now ignored. This fixes an issue where the unit file
    would sometimes be loaded from such a symlink, leading
    to non-deterministic unit contents.

  - Filtering of kernel threads is improved. This fixes an
    issues with newer kernels where hybrid kernel/user
    threads are used by bpfilter.

  - 'noresume' can be used on the kernel command line to
    force normal boot even if a hibernation images is
    present

  - Hibernation is not advertised if resume= is not present
    on the kernenl command line

  - Hibernation/Suspend/... modes can be disabled using
    AllowSuspend=, AllowHibernation=,
    AllowSuspendThenHibernate=, AllowHybridSleep=

  - LOGO= and DOCUMENTATION_URL= are documented for the
    os-release file

  - The hashmap mempool is now only used internally in
    systemd, and is disabled for external users of the
    systemd libraries

  - Additional state is serialized/deserialized when logind
    is restarted, fixing the handling of user objects

  - Catalog entries for the journal are improved (#1639482)

  - If suspend fails, the post-suspend hooks are still
    called.

  - Various build issues on less-common architectures are
    fixed

No need to reboot or log out.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-c402eea18b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:systemd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"systemd-239-6.git9f3aed1.fc29")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd");
}
