#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1562.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119716);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-17204", "CVE-2018-17205", "CVE-2018-17206");

  script_name(english:"openSUSE Security Update : openvswitch (openSUSE-2018-1562)");
  script_summary(english:"Check for the openSUSE-2018-1562 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openvswitch to version 2.7.6 fixes the following
issues :

These security issues were fixed :

  - CVE-2018-17205: Prevent OVS crash when reverting old
    flows in bundle commit (bsc#1104467).

  - CVE-2018-17206: Avoid buffer overread in BUNDLE action
    decoding (bsc#1104467).

  - CVE-2018-17204:When decoding a group mod, it validated
    the group type and command after the whole group mod has
    been decoded. The OF1.5 decoder, however, tried to use
    the type and command earlier, when it might still be
    invalid. This caused an assertion failure (via
    OVS_NOT_REACHED) (bsc#1104467).

These non-security issues were fixed :

  - ofproto/bond: Fix bond reconfiguration race condition.

  - ofproto/bond: Fix bond post recirc rule leak.

  - ofproto/bond: fix interal flow leak of tcp-balance bond

  - systemd: Restart openvswitch service if a daemon crashes

  - conntrack: Fix checks for TCP, UDP, and IPv6 header
    sizes.

  - ofp-actions: Fix translation of set_field for nw_ecn

  - netdev-dpdk: Fix mempool segfault.

  - ofproto-dpif-upcall: Fix flow setup/delete race.

  - learn: Fix memory leak in learn_parse_sepc()

  - netdev-dpdk: fix mempool_configure error state

  - vswitchd: Add --cleanup option to the 'appctl exit'
    command

  - ofp-parse: Fix memory leak on error path in
    parse_ofp_group_mod_file().

  - actions: Fix memory leak on error path in
    parse_ct_lb_action().

  - dpif-netdev: Fix use-after-free error in
    reconfigure_datapath().

  - bridge: Fix memory leak in bridge_aa_update_trunks().

  - dpif-netlink: Fix multiple-free and fd leak on error
    path.

  - ofp-print: Avoid array overread in
    print_table_instruction_features().

  - flow: Fix buffer overread in flow_hash_symmetric_l3l4().

  - systemd: start vswitchd after udev

  - ofp-util: Check length of buckets in
    ofputil_pull_ofp15_group_mod().

  - ovsdb-types: Fix memory leak on error path.

  - tnl-ports: Fix loss of tunneling upon removal of a
    single tunnel port.

  - netdev: check for NULL fields in netdev_get_addrs

  - netdev-dpdk: vhost get stats fix.

  - netdev-dpdk: use 64-bit arithmetic when converting
    rates.

  - ofp-util: Fix buffer overread in
    ofputil_decode_bundle_add().

  - ofp-util: Fix memory leaks on error cases in
    ofputil_decode_group_mod().

  - ofp-util: Fix memory leaks when parsing OF1.5 group
    properties.

  - ofp-actions: Fix buffer overread in
    decode_LEARN_specs().

  - flow: Fix buffer overread for crafted IPv6 packets.

  - ofp-actions: Properly interpret 'output:in_port'.

  - ovs-ofctl: Avoid read overrun in ofperr_decode_msg().

  - odp-util: Avoid misaligned references to ip6_hdr.

  - ofproto-dpif-upcall: Fix action attr iteration.

  - ofproto-dpif-upcall: Fix key attr iteration.

  - netdev-dpdk: vhost get stats fix.

  - netdev-dpdk: use 64-bit arithmetic when converting
    rates.

  - ofp-util: Fix buffer overread in
    ofputil_decode_bundle_add().

  - ofp-util: Fix memory leaks on error cases in
    ofputil_decode_group_mod().

  - ofp-util: Fix memory leaks when parsing OF1.5 group
    properties.

  - odp-util: Fix buffer overread in parsing string form of
    ODP flows.

  - ovs-vsctl: Fix segfault when attempting to del-port from
    parent bridge.

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104467"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openvswitch packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-central");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-central-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-host-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-ovn-vtep-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-vtep-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-debuginfo-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-debugsource-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-devel-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-central-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-central-debuginfo-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-common-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-common-debuginfo-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-docker-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-host-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-host-debuginfo-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-vtep-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-ovn-vtep-debuginfo-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-pki-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-test-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-test-debuginfo-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-vtep-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvswitch-vtep-debuginfo-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-openvswitch-2.7.6-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-openvswitch-test-2.7.6-19.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvswitch / openvswitch-debuginfo / openvswitch-debugsource / etc");
}
