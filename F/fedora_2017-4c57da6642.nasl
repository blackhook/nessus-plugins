#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-4c57da6642.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101179);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-9831", "CVE-2017-9832");
  script_xref(name:"FEDORA", value:"2017-4c57da6642");

  script_name(english:"Fedora 25 : libmtp (2017-4c57da6642)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libmtp 1.1.13 =============

Christophe Vu-Brugier (1) :

  - added GoPro HERO5 Black

Emeric Grange (2) :

  - added GoPro HERO5 Session

  - rename F5321 into XPeria X Compact

Gaute Hope (2) :

  - add GoPro Hero+

  - add mtp-detect for GoPro Hero+

Jerry Zhang (1) :

  - Update Google device strings, add (PTP+ADB) id

Marcus Meissner (69) :

  - added archos diamond s
    https://sourceforge.net/p/libmtp/support-requests/222/

  - added bq aquaris x5
    https://sourceforge.net/p/libmtp/support-requests/224/

  - added lenovo k910ss
    https://sourceforge.net/p/libmtp/bugs/1597/

  - zuk z1 second id
    https://sourceforge.net/p/libmtp/bugs/1596/

  - zuk z1 log

  - added cat s60
    https://sourceforge.net/p/libmtp/feature-requests/176/

  - oneplus one 3 log

  - added archos diamonds ,
    https://sourceforge.net/p/libmtp/support-requests/222/

  - added another alcatel idol 3 id
    https://sourceforge.net/p/libmtp/bugs/1605/

  - added tp-link neffos c5
    https://sourceforge.net/p/libmtp/bugs/1606/

  - added caterpillar cat s40
    https://sourceforge.net/p/libmtp/bugs/1603/

  - added lenovo vibe note k5
    https://sourceforge.net/p/libmtp/bugs/1608/

  - added BLU studio energy x2 phone adjusted the other BLU
    id to 4017

  - added huawei y560-l01
    https://sourceforge.net/p/libmtp/feature-requests/177/

  - intex aqua fish
    https://sourceforge.net/p/libmtp/bugs/1613/

  - added bq aquarius x5 (another id)
    https://sourceforge.net/p/libmtp/feature-requests/181/

  - added HTC Butterfly x920e
    https://sourceforge.net/p/libmtp/bugs/1615/

  - Motorola Pro+ added
    https://sourceforge.net/p/libmtp/feature-requests/189/

  - added Lenovo A706
    https://sourceforge.net/p/libmtp/support-requests/232/

  - added sony f5231
    https://sourceforge.net/p/libmtp/support-requests/230/

  - added Huawei Y360-U61
    https://sourceforge.net/p/libmtp/feature-requests/186/
    https://bugs.launchpad.net/ubuntu/+source/libmtp/+bug/15
    72658

  - added acer liquid z220
    https://sourceforge.net/p/libmtp/support-requests/228/

  - added lenovo k920
    https://sourceforge.net/p/libmtp/bugs/1595/

  - replace the major.version parsing logic by sscanf, allow
    a non-minor entry (as seen on Samsung)
    https://sourceforge.net/p/libmtp/bugs/1593/

  - added lenovo b smartphone
    https://sourceforge.net/p/libmtp/bugs/1624/

  - added lenovo P1ma40P
    https://sourceforge.net/p/libmtp/support-requests/235/

  - added HUAWEI Y320-U10
    https://sourceforge.net/p/libmtp/bugs/1629/

  - added huawei frd l09
    https://sourceforge.net/p/libmtp/bugs/1626/

  - htc desire 626g dual sim
    https://sourceforge.net/p/libmtp/bugs/1632/

  - render opcodes as opcodes, not ofc. render event names

  - added Kyocera Hydra Wave (model C6740N, Android version
    5.1)
    https://sourceforge.net/p/libmtp/feature-requests/192/

  - added SHARP SHV35 AQUOS U
    https://sourceforge.net/p/libmtp/feature-requests/192/

  - iriver ak70 https://sourceforge.net/p/libmtp/bugs/1634/

  - Intex AquaFish SailFish OS
    https://sourceforge.net/p/libmtp/feature-requests/201/

  - added TP-Link Neffos C5 MAX
    https://sourceforge.net/p/libmtp/feature-requests/197/

  - added tp-link neffos y5l
    https://sourceforge.net/p/libmtp/feature-requests/196/

  - added tp-link neffos y5
    https://sourceforge.net/p/libmtp/feature-requests/195/

  - added Blephone lephone T7+
    https://sourceforge.net/p/libmtp/feature-requests/194/

  - added Archos 101b Oxygen
    https://sourceforge.net/p/libmtp/bugs/1637

  - Merge /u/drzap/libmtp/ branch gopro_heroplus into master

  - added Huawei Nova
    https://sourceforge.net/p/libmtp/bugs/1640/

  - added acer liquid zest plus

  - added sony xperia z5 debug data
    https://sourceforge.net/p/libmtp/bugs/1631/

  - added blu energy x lte data

  - added lenovo k5

  - added Lenovo TAB 2 A10-30
    https://sourceforge.net/p/libmtp/feature-requests/204/

  - added ASUS ME581CL
    https://sourceforge.net/p/libmtp/bugs/1642/

  - added Nubia Z9 Max 'NX512j'
    https://sourceforge.net/p/libmtp/bugs/1646/

  - added Huawei Y360-U03
    https://sourceforge.net/p/libmtp/feature-requests/205/

  - nokia lumia 550

  - added Sony XPeria XA
    https://sourceforge.net/p/libmtp/bugs/1649/

  - added rim blackberry dtek 60
    https://sourceforge.net/p/libmtp/bugs/1658/

  - added nextbit robin
    https://sourceforge.net/p/libmtp/bugs/1663/

  - added lenovo k4 vibe
    https://sourceforge.net/p/libmtp/bugs/1664/

  - added archos diamond 55 selfie
    https://sourceforge.net/p/libmtp/feature-requests/209/

  - added yota yotaphone
    https://sourceforge.net/p/libmtp/bugs/1661/

  - added Asus Zenfone Go (ZC500TG)
    https://sourceforge.net/p/libmtp/feature-requests/208/

  - Archos 70b Neon
    https://sourceforge.net/p/libmtp/bugs/1660/

  - added sony xperia xz
    https://sourceforge.net/p/libmtp/feature-requests/207/

  - imported ptp* from libgphoto2

  - Merge /u/cvubrugier/libmtp/ branch master into master

  - added Lenovo S960
    https://sourceforge.net/p/libmtp/bugs/1673/

  - wrong render command, this is opcode not ofc

  - Fixed getpartialobject on non-x86_64 systems

  - Merge branch 'master' of
    ssh://git.code.sf.net/p/libmtp/code

  - add casts for varargs from 64bit to 32bit

  - Reenable MTP GetObjectProplist for Samsung Galaxy
    Models. (Seems to work on my S7) Reenable also for
    Motorola G2. added POINT OF VIEW TAB-I847
    https://sourceforge.net/p/libmtp/feature-requests/215/

  - adjusted G2 entry

  - release 1.1.13

Stanis&#x142;aw Pitucha (1) :

  - Add LIBMTP_FILES_AND_FOLDERS_ROOT and fix examples

libmtp 1.1.12 =============

  - Changes in the 1.1.12 release are mostly USB id
    additions

  - A new asynchronous function to check for events has also
    been added.

Jocelyn Mayer (1) :

  - added Acer Iconia One 10
    https://sourceforge.net/p/libmtp/bugs/1568/

Marcus Meissner (69) :

  - added sony xperia e1 ids
    https://sourceforge.net/p/libmtp/support-requests/207/

  - added debuginfo for marshall london phone
    https://sourceforge.net/p/libmtp/bugs/1520/

  - added iRulu X1si
    https://sourceforge.net/p/libmtp/bugs/1521/

  - hook in travis support

  - merge accumulated ptp lowlevel changes from libgphoto2.

  - run autogen.sh instead of configure

  - avoid question for autoupdateing

  - always build with a libusb avoid failing autoreconf, as
    we run autogen.sh

  - try to find libtoolize

  - try to find libtool harder

  - hmm . libtool is there, but libtoolize is not

  - added xperia m5
    https://sourceforge.net/p/libmtp/bugs/1527/

  - Caterpillar S50 added
    https://sourceforge.net/p/libmtp/bugs/1525/

  - add cat s50 2nd id

  - currently dont build for osx

  - added another m9 id
    https://sourceforge.net/p/libmtp/bugs/1508/

  - added haier ct715
    https://sourceforge.net/p/libmtp/support-requests/208/

  - added lenovo k900
    https://sourceforge.net/p/libmtp/bugs/1529/

  - added letv 1s
    https://sourceforge.net/p/libmtp/support-requests/210/

  - amazon fire 8 hd
    https://sourceforge.net/p/libmtp/feature-requests/158/

  - added lenovo vibe x
    https://sourceforge.net/p/libmtp/bugs/1531/

  - added LeTv X800 Android phone (libmtp-discuss)
    https://sourceforge.net/p/libmtp/bugs/1542/

  - added another wileyfox swift id
    https://sourceforge.net/p/libmtp/feature-requests/159/

  - added Sony Xperia C4 Dual
    https://sourceforge.net/p/libmtp/support-requests/212/

  - Motorola Droid Turbo 2
    https://sourceforge.net/p/libmtp/bugs/1539/

  - added Sony WALKMAN NWZ-E474
    https://sourceforge.net/p/libmtp/bugs/1540/

  - added BQ Aquaris M5.5
    https://sourceforge.net/p/libmtp/bugs/1541/

  - asus zenpad 80 added
    https://sourceforge.net/p/libmtp/bugs/1546/

  - acer z530 16GB
    https://sourceforge.net/p/libmtp/bugs/1534/

  - added htc 626 detection log
    https://sourceforge.net/p/libmtp/bugs/1538/

  - zuk z1 added https://sourceforge.net/p/libmtp/bugs/1545/

  - added lenovo vibe p1 pro
    https://sourceforge.net/p/libmtp/support-requests/213/

  - htc desire 626s
    https://sourceforge.net/p/libmtp/bugs/1543/

  - added asus fonepad 8
    https://sourceforge.net/p/libmtp/bugs/1548/

  - fairphone 2 os
    https://sourceforge.net/p/libmtp/support-requests/214/

  - htc desire 626s debug log
    https://sourceforge.net/p/libmtp/bugs/1543/

  - lenovo k3 note debug data
    https://sourceforge.net/p/libmtp/feature-requests/162/

  - added acer z630
    https://sourceforge.net/p/libmtp/bugs/1552/

  - added lenovo a3500-fl
    https://sourceforge.net/p/libmtp/bugs/1556/

  - BQ Aquaris M10 Ubuntu Edition Full HD
    https://sourceforge.net/p/libmtp/feature-requests/163/

  - added Kazam Trooper 650 4G
    https://sourceforge.net/p/libmtp/bugs/1554/

  - Blackberry Priv
    https://sourceforge.net/p/libmtp/bugs/1551/

  - bq aquarius avila cooler
    https://sourceforge.net/p/libmtp/bugs/1558/

  - lenovo vibe k4 note
    https://sourceforge.net/p/libmtp/bugs/1562/

  - Kyocera Hydro Elite
    https://sourceforge.net/p/libmtp/feature-requests/164/

  - LG V10 https://sourceforge.net/p/libmtp/bugs/1559/

  - added infocus m808
    https://sourceforge.net/p/libmtp/bugs/1567/

  - meizu pro 5 ubuntu phone added
    https://sourceforge.net/p/libmtp/bugs/1563/

  - added another htc m9 variant
    https://sourceforge.net/p/libmtp/support-requests/217/

  - added Recon Instruments Snow2 HUD and Recon Instruments
    Jet

  - LeTV X5001s added
    https://sourceforge.net/p/libmtp/bugs/1574/

  - added lenovo phab plus
    https://sourceforge.net/p/libmtp/bugs/1572/

  - Archos 101 xenon lite
    https://sourceforge.net/p/libmtp/bugs/1573/

  - Huawei Android Phone H60-L12
    https://sourceforge.net/p/libmtp/bugs/1550/

  - bravis a401 neo added
    https://sourceforge.net/p/libmtp/bugs/1553/

  - added lenovo TAB S8-50F
    https://sourceforge.net/p/libmtp/support-requests/219/

  - added BLU STUDIO ENERGY 2
    https://sourceforge.net/p/libmtp/bugs/1575/

  - nVidia Jetson TX1
    https://sourceforge.net/p/libmtp/bugs/1582/

  - fix indentation for gcc6

  - letv X800
    https://sourceforge.net/p/libmtp/support-requests/220/

  - Archos 40 Helium phone
    https://sourceforge.net/p/libmtp/bugs/1581/

  - Acer A1-841 https://sourceforge.net/p/libmtp/bugs/1579/

  - added Nokia N1
    https://sourceforge.net/p/libmtp/support-requests/221/

  - added Huawei P9 Plus
    https://sourceforge.net/p/libmtp/feature-requests/173/

  - added archos 50d neon
    https://sourceforge.net/p/libmtp/bugs/1587/

  - fixed c4 dual names

  - YotaPhone C9660
    https://sourceforge.net/p/libmtp/support-requests/127/

  - added Cubot X17
    https://sourceforge.net/p/libmtp/feature-requests/161/

  - 1.1.12 release

Philip Langdale (1) :

  - [events] Add an asynchronous function to check for
    events

Profpatsch (1) :

  - added jolla sailfish 0a07 id

Robert Reardon (1) :

  - added Jolla phone

----

Support lots of new MTP devices.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-4c57da6642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://sourceforge.net/p/libmtp/feature-requests/186/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libmtp package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libmtp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"libmtp-1.1.13-1.fc25")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmtp");
}
