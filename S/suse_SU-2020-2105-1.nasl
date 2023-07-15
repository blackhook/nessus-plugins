#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2105-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(139308);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2019-19462",
    "CVE-2019-20810",
    "CVE-2019-20812",
    "CVE-2020-0305",
    "CVE-2020-10135",
    "CVE-2020-10711",
    "CVE-2020-10732",
    "CVE-2020-10751",
    "CVE-2020-10766",
    "CVE-2020-10767",
    "CVE-2020-10768",
    "CVE-2020-10773",
    "CVE-2020-10781",
    "CVE-2020-12656",
    "CVE-2020-12769",
    "CVE-2020-12771",
    "CVE-2020-12888",
    "CVE-2020-13143",
    "CVE-2020-13974",
    "CVE-2020-14416",
    "CVE-2020-15393",
    "CVE-2020-15780"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : kernel (SUSE-SU-2020:2105-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various
security and bugfixes.

The following security bugs were fixed :

CVE-2019-19462: relay_open in kernel/relay.c in the Linux kernel
allowed local users to cause a denial of service (such as relay
blockage) by triggering a NULL alloc_percpu result (bnc#1158265).

CVE-2019-20810: Fixed a memory leak in go7007_snd_init in
drivers/media/usb/go7007/snd-go7007.c because it did not call
snd_card_free for a failure path (bnc#1172458).

CVE-2019-20812: An issue was discovered in the
prb_calc_retire_blk_tmo() function in net/packet/af_packet.c could
result in a denial of service (CPU consumption and soft lockup) in a
certain failure case involving TPACKET_V3 (bnc#1172453).

CVE-2020-0305: In cdev_get of char_dev.c, there is a possible
use-after-free due to a race condition. This could lead to local
escalation of privilege with System execution privileges needed. User
interaction is not needed for exploitation (bnc#1174462).

CVE-2020-10135: Legacy pairing and secure-connections pairing
authentication in Bluetooth&Acirc;&reg; BR/EDR Core Specification v5.2
and earlier may have allowed an unauthenticated user to complete
authentication without pairing credentials via adjacent access. An
unauthenticated, adjacent attacker could impersonate a Bluetooth
BR/EDR master or slave to pair with a previously paired remote device
to successfully complete the authentication procedure without knowing
the link key (bnc#1171988).

CVE-2020-10711: A NULL pointer dereference flaw was found in the
SELinux subsystem in versions This flaw occurs while importing the
Commercial IP Security Option (CIPSO) protocol's category bitmap into
the SELinux extensible bitmap via the' ebitmap_netlbl_import' routine.
This flaw allowed a remote network user to crash the system kernel,
resulting in a denial of service (bnc#1171191).

CVE-2020-10732: A flaw was found in the implementation of Userspace
core dumps. This flaw allowed an attacker with a local account to
crash a trivial program and exfiltrate private kernel data
(bnc#1171220).

CVE-2020-10751: A flaw was found in the SELinux LSM hook
implementation, where it incorrectly assumed that an skb would only
contain a single netlink message. The hook would incorrectly only
validate the first netlink message in the skb and allow or deny the
rest of the messages within the skb with the granted permission
without further processing (bnc#1171189).

CVE-2020-10766: Fixed an issue which allowed an attacker with a local
account to disable SSBD protection (bnc#1172781).

CVE-2020-10767: Fixed an issue where Indirect Branch Prediction
Barrier was disabled in certain circumstances, leaving the system open
to a spectre v2 style attack (bnc#1172782).

CVE-2020-10768: Fixed an issue with the prctl() function, where
indirect branch speculation could be enabled even though it was
diabled before (bnc#1172783).

CVE-2020-10773: Fixed a memory leak on s390/s390x, in the
cmm_timeout_hander in file arch/s390/mm/cmm.c (bnc#1172999).

CVE-2020-10781: A zram sysfs resource consumption was fixed
(bnc#1173074).

CVE-2020-12656: Fixed a memory leak in gss_mech_free in the
rpcsec_gss_krb5 implementation, caused by a lack of certain
domain_release calls (bnc#1171219).

CVE-2020-12769: An issue was discovered in drivers/spi/spi-dw.c
allowed attackers to cause a panic via concurrent calls to dw_spi_irq
and dw_spi_transfer_one (bnc#1171983).

CVE-2020-12771: An issue was discovered in btree_gc_coalesce in
drivers/md/bcache/btree.c has a deadlock if a coalescing operation
fails (bnc#1171732).

CVE-2020-12888: The VFIO PCI driver mishandled attempts to access
disabled memory space (bnc#1171868).

CVE-2020-13143: gadget_dev_desc_UDC_store in
drivers/usb/gadget/configfs.c relies on kstrdup without considering
the possibility of an internal '\0' value, which allowed attackers to
trigger an out-of-bounds read (bnc#1171982).

CVE-2020-13974: Fixed a integer overflow in drivers/tty/vt/keyboard.c,
if k_ascii is called several times in a row (bnc#1172775).

CVE-2020-14416: Fixed a race condition in tty->disc_data handling in
the slip and slcan line discipline could lead to a use-after-free.
This affects drivers/net/slip/slip.c and drivers/net/can/slcan.c
(bnc#1162002).

CVE-2020-15393: Fixed a memory leak in usbtest_disconnect
(bnc#1173514).

CVE-2020-15780: An issue was discovered in
drivers/acpi/acpi_configfs.c where injection of malicious ACPI tables
via configfs could be used by attackers to bypass lockdown and secure
boot restrictions, aka CID-75b0cea7bf30 (bnc#1173573).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1058115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1071995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1085030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1148868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1152472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1153274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1154492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1155518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1155798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1157169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158265");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1160947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1161495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1164648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1164777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1164780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1165211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1165933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1165975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1166985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1167104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1167651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1167773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1168230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1168779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1168838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1168959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172062");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172064");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172069");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172342");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172394");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173818");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173833");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173844");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174116");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174127");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174129");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174527");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=962849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19462/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20810/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20812/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-0305/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10135/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10711/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10732/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10751/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10766/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10767/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10768/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10773/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10781/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12656/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12769/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12771/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12888/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13143/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13974/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14416/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15393/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15780/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202105-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?965229cb");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15-SP2 :

zypper in -t patch SUSE-SLE-Product-WE-15-SP2-2020-2105=1

SUSE Linux Enterprise Module for Live Patching 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Live-Patching-15-SP2-2020-2105=1

SUSE Linux Enterprise Module for Legacy Software 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Legacy-15-SP2-2020-2105=1

SUSE Linux Enterprise Module for Development Tools 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP2-2020-2105=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2020-2105=1

SUSE Linux Enterprise High Availability 15-SP2 :

zypper in -t patch SUSE-SLE-Product-HA-15-SP2-2020-2105=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15780");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-13974");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-debuginfo-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-debugsource-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-devel-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-devel-debuginfo-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-base-5.3.18-24.9.1.9.2.6")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-debuginfo-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-debugsource-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-devel-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-devel-debuginfo-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-obs-build-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-obs-build-debugsource-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-syms-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"reiserfs-kmp-default-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"reiserfs-kmp-default-debuginfo-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-debuginfo-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-debugsource-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-devel-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-devel-debuginfo-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-base-5.3.18-24.9.1.9.2.6")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-debuginfo-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-debugsource-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-devel-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-devel-debuginfo-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-obs-build-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-obs-build-debugsource-5.3.18-24.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-syms-5.3.18-24.9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
