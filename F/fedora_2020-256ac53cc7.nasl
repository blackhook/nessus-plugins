#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-256ac53cc7.
#

include("compat.inc");

if (description)
{
  script_id(137788);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2019-8377", "CVE-2020-12740");
  script_xref(name:"FEDORA", value:"2020-256ac53cc7");

  script_name(english:"Fedora 31 : tcpreplay (2020-256ac53cc7)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This release contains bug fixes only (which includes security fixes) :

  - Increase cache buffers size to accomodate VLAN edits
    (#594)

  - Correct L2 header length to correct IP header offset
    (#583)

  - Fix warnings from gcc version 10 (#580)

  - Heap Buffer Overflow in randomize_iparp (#579)

  - Use after free in get_ipv6_next (#578)

  - Heap Buffer Overflow in git_ipv6_next (#576)

  - Call pcap_freecode() on pcap_compile() (#572)

  - Increase max snaplen to 262144 (#571)

  - Fix divide by zero in fuzzing (#570)

  - Unique IP repeats at very high iteration counts (#566)

  - Fails to compile on FreeBSD amd64 13.0 (#558)

  - Heap Buffer Overflow in do_checksum (#556) (#577)

  - Attempt to correct corrupt pcap files, if possible
    (#557)

  - Fix GCC v10 warnings (#555)

  - Remove some duplicated SOURCES entries (#551)

  - Expand /dev/bpfX hard limit to fix macOS Mojave (#550)

  - Implement --loopdelay-ms when using --loop=0 (#546)

  - Heap overflow packet2tree and get_l2len (#530)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-256ac53cc7"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected tcpreplay package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8377");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tcpreplay");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/25");
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
if (! preg(pattern:"^31([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 31", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC31", reference:"tcpreplay-4.3.3-1.fc31")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tcpreplay");
}
