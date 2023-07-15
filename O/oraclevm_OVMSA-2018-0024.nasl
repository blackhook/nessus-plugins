#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0024.
#

include("compat.inc");

if (description)
{
  script_id(107249);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/10");

  script_cve_id("CVE-2018-5732", "CVE-2018-5733");
  script_xref(name:"IAVB", value:"2018-B-0034-S");

  script_name(english:"OracleVM 3.3 : dhcp (OVMSA-2018-0024)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Added oracle-errwarn-message.patch

  - Resolves: #1550085 - CVE-2018-5733 Avoid reference
    overflow

<[12:4.1.1-53.P1.2

  - Resolves: #1550083 - CVE-2018-5732 Avoid options buffer
    overflow

  - Resolves: #1063217 - failover hangs with both
    potential-conflict

  - Resolves: #1363790 - dhclient does not update routing
    table after the lease &nbsp  expiry

  - Resolves: #1321945 - dhclient hook script for Azure
    cloud

  - send unicast request/release via correct interface
    (#1297445)

  - Lease table overflow crash. (#1133917)

  - Add ignore-client-uids option. (#1196768)

  - dhclient-script: it's OK if the arping reply comes from
    our system. (#1204095)

  - VLAN ID is only bottom 12-bits of TCI. (#1259552)

  - dhclient: Make sure link-local address is ready in
    stateless mode. (#1263466)

  - dhclient-script: make_resolv_conf: Keep old nameservers
    &nbsp  if server sends domain-name/search, but no
    nameservers. (#1269595)

  - Fix dhcrelay init script too. (#1187967)

  - Actually take IB MAC address into account when creating
    seed (#1185075)

  - Improve seeding the random number generator in dhclient
    (#1185075)

  - Fix dhcrelay6 init script (#1187967)

  - dhcrelay -6 was not working due to patch for #1001742
    (#1151054)

  - option 97 - pxe-client-id (#1058674)

  - dhclient-script: PREINIT6: make sure link-local address
    is available (#1130804)

  - dhcpd generates spurious responses when seeing requests
    &nbsp  from vlans on plain interface (#1150587)

  - Fix dhcpd/dhcrelay segfault if interface name longer
    than IFNAMSIZ (#1102662)

  - Fix parsing of lease file dates & times on 64-bit
    platforms (#1099698)

  - Fix dhcpd.leases reverting to root:root on every dhcpd
    start (#1067142) &nbsp  New patch 'paranoia' merged with
    older 'paranoia-pid' patch

  - Add init script for dhcrelay IPv6 version (#1053155)

  - Fix handling of UDP packets with checksum 0xffff.
    (#1015997)

  - Add GUIDs in the DHCP logs for IPoIB. (#1064416)

  - Rotate the lease file when running in v6 mode.
    (#1053431)

  - Resolves: #1001742 - dhclient: Make setsockopt not-fatal
    also for SO_REUSEPORT

  - Resolves: #1001742 - dhclient: Bind socket to interface
    also for IPv6

  - Don't crash on aliased infiniband interface. (#996518)

  - various memory leaks in omapi (#978420)

  - Modify the reply handling in the server code to send to
    a specified port &nbsp  rather than to the source port
    for the incoming message. (#952126)

  - Multiple key statements in zone definition causes
    inappropriate error (#919221)

  - Make sure range6 is correct for subnet6 where it's
    declared (#902966)

  - Relay no longer crashes, when DHCP packet is received
    over interface &nbsp  without any IPv4 address assigned.
    (#863936)

  - Expose next-server DHCPv4 option to dhclient script.
    (#658855)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-March/000835.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57dbebd9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dhclient / dhcp-common packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"dhclient-4.1.1-53.P1.0.1.el6_9.3")) flag++;
if (rpm_check(release:"OVS3.3", reference:"dhcp-common-4.1.1-53.P1.0.1.el6_9.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhclient / dhcp-common");
}
