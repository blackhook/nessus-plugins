#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-166b220ff1.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120954);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-13112", "CVE-2018-17580", "CVE-2018-17582", "CVE-2018-17974", "CVE-2018-18407", "CVE-2018-18408");
  script_xref(name:"FEDORA", value:"2018-166b220ff1");

  script_name(english:"Fedora 28 : tcpreplay (2018-166b220ff1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This release (4.3.1) contains bug fixes only :

  - Fix checkspell detected typos (#531)

  - Heap overflow packet2tree and get_l2len (#530)

This is Tcpreplay suite 4.3.0

This release contains several bug fixes and enhancements :

  - Fix maxOS TOS checksum failure (#524)

  - TCP sequence edits seeding (#514)

  - Fix issues identifed by Codacy (#493)

  - CVE-2018-18408 use-after-free in post_args (#489)

  - CVE-2018-18407 heap-buffer-overflow csum_replace4 (#488)

  - CVE-2018-17974 heap-buffer-overflow dlt_en10mb_encode
    (#486)

  - CVE-2018-17580 heap-buffer-overflow fast_edit_packet
    (#485)

  - CVE-2018-17582 heap-buffer-overflow in get_next_packet
    (#484)

  - Out-of-tree build (#482)

  - CVE-2018-13112 heap-buffer-overflow in get_l2len (#477
    dup #408)

  - Closing stdin on pipe (#479)

  - Second pcap file hangs on multiplier option (#472)

  - Jumbo frame support for fragroute option (#466)

  - TCP sequence edit ACK corruption (#451)

  - TCP sequence number edit initial SYN packet should have
    zero ACK (#450)

  - Travis CI build fails due to new build images (#432)

  - Upgrade libopts to 5.18.12 to address version build
    issues (#430)

  - Add ability to change tcp SEQ/ACK numbers (#425)

  - Hang using loop and netmap options (#424)

  - tcpprep -S not working for large cache files (#423)

  - Unable to tcprewrite range of ports with --portmap
    (#422)

  - --maxsleep broken for values less than 1000 (#421)

  - -T flag breaks traffic replay timing (#419)

  - Respect 2nd packet timing (#418)

  - Avoid non-blocking behaviour when using STDIN (#416)

  - pcap containing >1020 packets produces invalid cache
    file (#415)

  - manpage typos (#413)

  - Fails to open tap0 on Zephyr (#411)

  - Heap-buffer-overflow in get_l2protocol (#410)

  - Heap-buffer-overflow in packet2tree (#409)

  - Heap-buffer-overflow in get_l2len (#408)

  - Heap-buffer-overflow in flow_decode (#407)

  - Rewrite zero IP total length field to match the actual
    packet length (#406)

  - Stack-buffer-overflow in tcpcapinfo (#405)

  - tcpprep --include option does not exclude (#404)

  - Negative-size-param memset in dlt_radiotap_get_80211
    (#402)

  - tcpeplay --verbose option not working (#398)

  - Fix replay when using --with-testnic (#178)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-166b220ff1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tcpreplay package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tcpreplay");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/07");
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
if (! preg(pattern:"^28([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 28", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC28", reference:"tcpreplay-4.3.1-1.fc28")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tcpreplay");
}
