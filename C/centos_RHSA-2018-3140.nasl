#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3140 and 
# CentOS Errata and Security Advisory 2018:3140 respectively.
#

include("compat.inc");

if (description)
{
  script_id(118995);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/03");

  script_cve_id("CVE-2015-9381", "CVE-2015-9382", "CVE-2017-18267", "CVE-2018-10733", "CVE-2018-10767", "CVE-2018-10768", "CVE-2018-12910", "CVE-2018-13988");
  script_xref(name:"RHSA", value:"2018:3140");

  script_name(english:"CentOS 7 : PackageKit / accountsservice / adwaita-icon-theme / appstream-data / at-spi2-atk / etc (CESA-2018:3140)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

GNOME is the default desktop environment of Red Hat Enterprise Linux.

Security Fix(es) :

* libsoup: Crash in soup_cookie_jar.c:get_cookies() on empty hostnames
(CVE-2018-12910)

* poppler: Infinite recursion in
fofi/FoFiType1C.cc:FoFiType1C::cvtGlyph() function allows denial of
service (CVE-2017-18267)

* libgxps: heap based buffer over read in ft_font_face_hash function
of gxps-fonts.c (CVE-2018-10733)

* libgxps: Stack-based buffer overflow in calling glib in
gxps_images_guess_content_type of gcontenttype.c (CVE-2018-10767)

* poppler: NULL pointer dereference in
Annot.h:AnnotPath::getCoordsLength() allows for denial of service via
crafted PDF (CVE-2018-10768)

* poppler: out of bounds read in pdfunite (CVE-2018-13988)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank chenyuan (NESA Lab) for reporting
CVE-2018-10733 and CVE-2018-10767 and Hosein Askari for reporting
CVE-2018-13988.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.6 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-announce/2019-February/023179.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17ecaea3"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005310.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc395609"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005313.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d3c0811"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005318.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e681e0f7"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005320.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?941e29e7"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005321.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b777265f"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005322.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4d6e66f"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005326.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f3eb241"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005332.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bdbd865"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005333.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33add420"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005334.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ef1c1e4"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005338.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71c45778"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005341.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f44e852b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005343.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33c7ef2a"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005344.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70192799"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005355.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca0dcb0b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005356.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?134eaaca"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005357.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c400ed2"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005367.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f94c886c"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005370.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4fe84c4a"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005371.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1483302"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005373.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1a7d956"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005374.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff8ed1ab"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005375.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?903eed58"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005376.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?728c355b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005377.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4cb1e058"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005381.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?940cfbc2"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005383.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21e31f9d"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005384.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cfbc706d"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005386.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a6bbcba"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005389.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ea65178"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005390.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bb94afb"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005392.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4b8adfa"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005394.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b35739f9"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005396.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f0c7bc5"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005397.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee5deb95"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005399.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70bb5421"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005400.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9644c436"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005405.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6113cdf7"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005406.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc2cd97b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005407.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a61611a"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005409.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?147927b6"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005410.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78ca0269"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005412.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24b26030"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005413.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?afd16bed"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005414.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6be8b36f"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005415.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c039da3"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005416.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34f2efba"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005417.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45b34bb1"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005418.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?173270f9"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005419.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33174770"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005420.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55bea613"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005421.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a6deccd"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005422.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e09fb27"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005423.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d217f71b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005424.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3ca0bcc"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005425.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b6d25b0"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005426.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?562cf014"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005427.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3584f338"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005428.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47504943"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005429.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ee9ad75"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005430.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa421df5"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005431.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?280fe2ee"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005432.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?762d83f0"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005433.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef4dfba7"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005436.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a241907"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005437.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10b3c069"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005438.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1f21b9e"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005439.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22ebe9ed"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005440.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23d6a3d5"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005441.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6450226"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005442.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec132f43"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005443.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0a64e2c"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005444.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ee32f6b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005445.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30a5bc17"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005446.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d75e817"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005448.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e189d18"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005449.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?613e4275"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005450.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6004556b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005451.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b53615c6"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005452.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a139accd"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005455.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d35e3ef3"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005456.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f71a133d"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005457.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b4a1119c"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005458.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52142423"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005459.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?159f3c99"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005460.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8bacef4d"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005461.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?506da1a2"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005462.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d714298"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005463.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da806334"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005464.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b04c11c"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005465.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a313a29"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005467.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8523df33"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005483.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac2a01aa"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005491.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97b18c55"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005495.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?760570c4"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005496.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd0eaf37"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005502.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?331ed0db"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005503.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd265790"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005504.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb5e8b51"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005505.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03135625"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005507.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d70ddfa"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005508.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68b8b0f9"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005509.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa0e9f58"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005511.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6303489"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005512.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c57dfad8"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005513.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de514e0c"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005519.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1f9b7d9"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005521.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a9fa9a3"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005522.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e05f2b84"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005529.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64c53546"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005530.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58efd2bc"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005534.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b64e1de8"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005542.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9481cc1d"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005564.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d4c0055"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005567.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?707c08ab"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005570.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5253cc1a"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005571.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab85cc2a"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005587.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bf39d24"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005596.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed518e02"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005600.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bcc0e17c"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005612.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?497e81e6"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005614.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2ec8341"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005632.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4940893e"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005634.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?760b43af"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005646.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?090d6cd2"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005652.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa954c88"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005660.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?62c8fda2"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005677.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?93020b9e"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005681.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba30ab9b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005682.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?184d7b35"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005687.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ab30954"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005690.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c950533"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005693.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37155eda"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005698.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90aeac73"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005701.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a61e41a8"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005702.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ec760ee"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005703.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c294b807"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005708.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee325f11"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005709.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?752a3fd9"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005735.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e726ec2d"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005736.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81bed86f"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005737.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1c57321"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005741.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13208828"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12910");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit-command-not-found");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit-gstreamer-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit-gtk3-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit-yum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit-yum-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:accountsservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:accountsservice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:accountsservice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:adwaita-cursor-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:adwaita-gtk2-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:adwaita-icon-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:adwaita-icon-theme-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:appstream-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:at-spi2-atk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:at-spi2-atk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:at-spi2-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:at-spi2-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:atk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:atk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:baobab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bolt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:brasero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:brasero-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:brasero-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:brasero-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cairo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cairo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cairo-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cairo-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cairo-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cheese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cheese-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cheese-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:clutter-gst3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:clutter-gst3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:compat-exiv2-023");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:compat-libical1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:control-center-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dconf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dconf-editor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ekiga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:empathy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:eog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:eog-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince-dvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-bogofilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-ews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-ews-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-mapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-mapi-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-pst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-spamassassin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:file-roller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:file-roller-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:flatpak-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:flatpak-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:flatpak-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:folks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:folks-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:folks-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fontconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fontconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fontconfig-devel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fribidi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fribidi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fwupd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fwupd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fwupdate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fwupdate-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fwupdate-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fwupdate-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdm-pam-extensions-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-bookmarks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-bracketcompletion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-charmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-codecomment");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-colorpicker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-colorschemer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-commander");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-drawspaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-findinfiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-joinlines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-multiedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-smartspaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-synctex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-terminal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-textsize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-translate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugin-wordcompletion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-plugins-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:geoclue2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:geoclue2-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:geoclue2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:geoclue2-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:geocode-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:geocode-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gjs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gjs-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glade-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glade-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib-networking");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib-networking-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2-fam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibmm24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibmm24-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibmm24-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-backgrounds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-bluetooth-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-bluetooth-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-boxes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-calculator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-classic-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-clocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-color-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-contacts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-desktop3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-desktop3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-desktop3-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-dictionary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-disk-utility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-documents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-documents-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-font-viewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-getting-started-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-getting-started-docs-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-getting-started-docs-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-getting-started-docs-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-getting-started-docs-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-getting-started-docs-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-getting-started-docs-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-getting-started-docs-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-getting-started-docs-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-getting-started-docs-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-getting-started-docs-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-initial-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-keyring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-keyring-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-online-accounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-online-accounts-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-online-miners");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-packagekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-packagekit-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-packagekit-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-packagekit-updater");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-screenshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-session-custom-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-session-wayland-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-session-xsession");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-settings-daemon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-alternate-tab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-apps-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-auto-move-windows");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-dash-to-dock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-drive-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-launch-new-instance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-native-window-placement");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-no-hot-corner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-panel-favorites");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-places-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-screenshot-window-sizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-systemMonitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-top-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-updates-dialog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-user-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-window-list");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-windowsNavigator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-workspace-indicator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-software");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-software-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-software-editor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-system-monitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-terminal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-terminal-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-themes-standard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-tweak-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-user-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gobject-introspection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gobject-introspection-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:google-noto-emoji-color-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:google-noto-emoji-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grilo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grilo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grilo-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gsettings-desktop-schemas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gsettings-desktop-schemas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gspell-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gspell-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gssdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gssdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gssdp-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gssdp-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1-plugins-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1-plugins-base-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1-plugins-base-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk-update-icon-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3-immodule-xim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3-immodules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtksourceview3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtksourceview3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtksourceview3-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gucharmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gucharmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gucharmap-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gupnp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gupnp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gupnp-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gupnp-igd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gupnp-igd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gupnp-igd-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-afc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-afp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-archive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-goa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-gphoto2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-mtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-smb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:harfbuzz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:harfbuzz-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:harfbuzz-icu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:json-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:json-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:json-glib-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libappstream-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libappstream-glib-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libappstream-glib-builder-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libappstream-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libchamplain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libchamplain-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libchamplain-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libchamplain-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcroco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcroco-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgdata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgdata-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgee-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgepub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgepub-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgexiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgexiv2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgnomekbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgnomekbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgovirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgtop2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgtop2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgweather");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgweather-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgxps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgxps-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgxps-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libical-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libical-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libical-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libical-glib-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libmediaart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libmediaart-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libmediaart-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libosinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libosinfo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libosinfo-vala");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpeas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpeas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpeas-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpeas-loader-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:librsvg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:librsvg2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:librsvg2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsecret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsecret-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsoup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsoup-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwayland-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwayland-cursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwayland-egl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwayland-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwnck3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwnck3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozjs52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozjs52-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus-sendto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openchange");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openchange-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openchange-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openchange-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:osinfo-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pango-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pango-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-cpp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-gexiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-pyatspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rest-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rhythmbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rhythmbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seahorse-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:shotwell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sushi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:totem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:totem-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:totem-pl-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:totem-pl-parser-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:upower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:upower-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:upower-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vala");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vala-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vala-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:valadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:valadoc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vte-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vte291");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vte291-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wayland-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wayland-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wayland-protocols-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkitgtk4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkitgtk4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkitgtk4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkitgtk4-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkitgtk4-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkitgtk4-plugin-process-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xdg-desktop-portal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xdg-desktop-portal-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xdg-desktop-portal-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yelp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yelp-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yelp-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yelp-xsl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:zenity");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-1.1.10-1.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-command-not-found-1.1.10-1.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-cron-1.1.10-1.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-glib-1.1.10-1.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-glib-devel-1.1.10-1.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-gstreamer-plugin-1.1.10-1.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-gtk3-module-1.1.10-1.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-yum-1.1.10-1.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-yum-plugin-1.1.10-1.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"accountsservice-0.6.50-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"accountsservice-devel-0.6.50-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"accountsservice-libs-0.6.50-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"adwaita-cursor-theme-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"adwaita-gtk2-theme-3.28-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"adwaita-icon-theme-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"adwaita-icon-theme-devel-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"appstream-data-7-20180614.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"at-spi2-atk-2.26.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"at-spi2-atk-devel-2.26.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"at-spi2-core-2.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"at-spi2-core-devel-2.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"atk-2.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"atk-devel-2.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"baobab-3.28.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bolt-0.4-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"brasero-3.12.2-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"brasero-devel-3.12.2-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"brasero-libs-3.12.2-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"brasero-nautilus-3.12.2-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cairo-1.15.12-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cairo-devel-1.15.12-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cairo-gobject-1.15.12-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cairo-gobject-devel-1.15.12-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cairo-tools-1.15.12-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cheese-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cheese-libs-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cheese-libs-devel-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"clutter-gst3-3.0.26-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"clutter-gst3-devel-3.0.26-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"compat-exiv2-023-0.23-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"compat-libical1-1.0.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"control-center-3.28.1-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"control-center-filesystem-3.28.1-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"dconf-0.28.0-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"dconf-devel-0.28.0-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"dconf-editor-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"devhelp-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"devhelp-devel-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"devhelp-libs-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ekiga-4.0.1-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"empathy-3.12.13-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"eog-3.28.3-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"eog-devel-3.28.3-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evince-3.28.2-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evince-browser-plugin-3.28.2-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evince-devel-3.28.2-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evince-dvi-3.28.2-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evince-libs-3.28.2-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evince-nautilus-3.28.2-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-3.28.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-bogofilter-3.28.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-data-server-3.28.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-data-server-devel-3.28.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-data-server-doc-3.28.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-data-server-langpacks-3.28.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-data-server-perl-3.28.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-data-server-tests-3.28.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-devel-3.28.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-devel-docs-3.28.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-ews-3.28.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-ews-langpacks-3.28.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-help-3.28.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-langpacks-3.28.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-mapi-3.28.3-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-mapi-langpacks-3.28.3-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-pst-3.28.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-spamassassin-3.28.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-tests-3.28.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"file-roller-3.28.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"file-roller-nautilus-3.28.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"flatpak-1.0.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"flatpak-builder-1.0.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"flatpak-devel-1.0.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"flatpak-libs-1.0.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"folks-0.11.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"folks-devel-0.11.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"folks-tools-0.11.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fontconfig-2.13.0-4.3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fontconfig-devel-2.13.0-4.3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fontconfig-devel-doc-2.13.0-4.3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"freetype-2.8-12.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"freetype-demos-2.8-12.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"freetype-devel-2.8-12.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fribidi-1.0.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fribidi-devel-1.0.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fwupd-1.0.8-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fwupd-devel-1.0.8-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fwupdate-12-5.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fwupdate-devel-12-5.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fwupdate-efi-12-5.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fwupdate-libs-12-5.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gcr-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gcr-devel-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gdk-pixbuf2-2.36.12-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gdk-pixbuf2-devel-2.36.12-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gdk-pixbuf2-tests-2.36.12-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gdm-3.28.2-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gdm-devel-3.28.2-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gdm-pam-extensions-devel-3.28.2-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-devel-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-bookmarks-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-bracketcompletion-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-charmap-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-codecomment-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-colorpicker-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-colorschemer-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-commander-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-drawspaces-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-findinfiles-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-joinlines-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-multiedit-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-smartspaces-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-synctex-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-terminal-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-textsize-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-translate-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugin-wordcompletion-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugins-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gedit-plugins-data-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"geoclue2-2.4.8-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"geoclue2-demos-2.4.8-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"geoclue2-devel-2.4.8-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"geoclue2-libs-2.4.8-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"geocode-glib-3.26.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"geocode-glib-devel-3.26.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gjs-1.52.3-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gjs-devel-1.52.3-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gjs-tests-1.52.3-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glade-3.22.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glade-devel-3.22.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glade-libs-3.22.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glib-networking-2.56.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glib-networking-tests-2.56.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glib2-2.56.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glib2-devel-2.56.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glib2-doc-2.56.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glib2-fam-2.56.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glib2-static-2.56.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glib2-tests-2.56.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glibmm24-2.56.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glibmm24-devel-2.56.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glibmm24-doc-2.56.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-backgrounds-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-bluetooth-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-bluetooth-libs-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-bluetooth-libs-devel-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-boxes-3.28.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-calculator-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-classic-session-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-clocks-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-color-manager-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-contacts-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-desktop3-3.28.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-desktop3-devel-3.28.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-desktop3-tests-3.28.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-devel-docs-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-dictionary-3.26.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-disk-utility-3.28.3-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-documents-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-documents-libs-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-font-viewer-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-getting-started-docs-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-getting-started-docs-cs-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-getting-started-docs-de-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-getting-started-docs-es-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-getting-started-docs-fr-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-getting-started-docs-gl-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-getting-started-docs-hu-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-getting-started-docs-it-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-getting-started-docs-pl-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-getting-started-docs-pt_BR-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-getting-started-docs-ru-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-initial-setup-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-keyring-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-keyring-pam-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-online-accounts-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-online-accounts-devel-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-online-miners-3.26.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-packagekit-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-packagekit-common-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-packagekit-installer-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-packagekit-updater-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-screenshot-3.26.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-session-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-session-custom-session-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-session-wayland-session-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-session-xsession-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-settings-daemon-3.28.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-settings-daemon-devel-3.28.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-3.28.3-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-alternate-tab-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-apps-menu-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-auto-move-windows-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-common-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-dash-to-dock-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-drive-menu-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-launch-new-instance-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-native-window-placement-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-no-hot-corner-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-panel-favorites-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-places-menu-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-screenshot-window-sizer-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-systemMonitor-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-top-icons-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-updates-dialog-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-user-theme-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-window-list-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-windowsNavigator-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-workspace-indicator-3.28.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-software-3.28.2-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-software-devel-3.28.2-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-software-editor-3.28.2-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-system-monitor-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-terminal-3.28.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-terminal-nautilus-3.28.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-themes-standard-3.28-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-tweak-tool-3.28.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-user-docs-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnote-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gobject-introspection-1.56.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gobject-introspection-devel-1.56.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gom-0.3.3-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gom-devel-0.3.3-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"google-noto-emoji-color-fonts-20180508-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"google-noto-emoji-fonts-20180508-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"grilo-0.3.6-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"grilo-devel-0.3.6-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"grilo-plugins-0.3.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gsettings-desktop-schemas-3.28.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gsettings-desktop-schemas-devel-3.28.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gspell-1.6.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gspell-devel-1.6.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gspell-doc-1.6.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gssdp-1.0.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gssdp-devel-1.0.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gssdp-docs-1.0.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gssdp-utils-1.0.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-plugins-base-1.10.4-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-plugins-base-devel-1.10.4-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-plugins-base-devel-docs-1.10.4-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-plugins-base-tools-1.10.4-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtk-doc-1.28-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtk-update-icon-cache-3.22.30-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtk3-3.22.30-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtk3-devel-3.22.30-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtk3-devel-docs-3.22.30-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtk3-immodule-xim-3.22.30-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtk3-immodules-3.22.30-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtk3-tests-3.22.30-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtksourceview3-3.24.8-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtksourceview3-devel-3.24.8-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtksourceview3-tests-3.24.8-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gucharmap-10.0.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gucharmap-devel-10.0.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gucharmap-libs-10.0.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gupnp-1.0.2-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gupnp-devel-1.0.2-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gupnp-docs-1.0.2-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gupnp-igd-0.2.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gupnp-igd-devel-0.2.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gupnp-igd-python-0.2.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gvfs-1.36.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gvfs-afc-1.36.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gvfs-afp-1.36.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gvfs-archive-1.36.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gvfs-client-1.36.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gvfs-devel-1.36.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gvfs-fuse-1.36.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gvfs-goa-1.36.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gvfs-gphoto2-1.36.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gvfs-mtp-1.36.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gvfs-smb-1.36.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gvfs-tests-1.36.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"harfbuzz-1.7.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"harfbuzz-devel-1.7.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"harfbuzz-icu-1.7.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"json-glib-1.4.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"json-glib-devel-1.4.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"json-glib-tests-1.4.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libappstream-glib-0.7.8-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libappstream-glib-builder-0.7.8-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libappstream-glib-builder-devel-0.7.8-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libappstream-glib-devel-0.7.8-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libchamplain-0.12.16-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libchamplain-demos-0.12.16-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libchamplain-devel-0.12.16-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libchamplain-gtk-0.12.16-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcroco-0.6.12-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcroco-devel-0.6.12-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgdata-0.17.9-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgdata-devel-0.17.9-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgee-0.20.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgee-devel-0.20.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgepub-0.6.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgepub-devel-0.6.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgexiv2-0.10.8-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgexiv2-devel-0.10.8-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgnomekbd-3.26.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgnomekbd-devel-3.26.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgovirt-0.3.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgovirt-devel-0.3.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgtop2-2.38.0-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgtop2-devel-2.38.0-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgweather-3.28.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgweather-devel-3.28.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgxps-0.3.0-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgxps-devel-0.3.0-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgxps-tools-0.3.0-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libical-3.0.3-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libical-devel-3.0.3-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libical-glib-3.0.3-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libical-glib-devel-3.0.3-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libical-glib-doc-3.0.3-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libmediaart-1.9.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libmediaart-devel-1.9.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libmediaart-tests-1.9.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libosinfo-1.1.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libosinfo-devel-1.1.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libosinfo-vala-1.1.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libpeas-1.22.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libpeas-devel-1.22.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libpeas-gtk-1.22.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libpeas-loader-python-1.22.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"librsvg2-2.40.20-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"librsvg2-devel-2.40.20-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"librsvg2-tools-2.40.20-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsecret-0.18.6-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsecret-devel-0.18.6-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsoup-2.62.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsoup-devel-2.62.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwayland-client-1.15.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwayland-cursor-1.15.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwayland-egl-1.15.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwayland-server-1.15.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwnck3-3.24.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwnck3-devel-3.24.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mozjs52-52.9.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mozjs52-devel-52.9.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mutter-3.28.3-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mutter-devel-3.28.3-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nautilus-3.26.3.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nautilus-devel-3.26.3.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nautilus-extensions-3.26.3.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nautilus-sendto-3.8.6-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openchange-2.3-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openchange-client-2.3-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openchange-devel-2.3-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openchange-devel-docs-2.3-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"osinfo-db-20180531-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pango-1.42.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pango-devel-1.42.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pango-tests-1.42.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-0.26.5-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-cpp-0.26.5-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-cpp-devel-0.26.5-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-demos-0.26.5-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-devel-0.26.5-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-glib-0.26.5-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-glib-devel-0.26.5-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-qt-0.26.5-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-qt-devel-0.26.5-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-utils-0.26.5-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python2-gexiv2-0.10.8-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python2-pyatspi-2.26.0-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rest-0.8.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rest-devel-0.8.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rhythmbox-3.4.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rhythmbox-devel-3.4.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"seahorse-nautilus-3.11.92-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"shotwell-0.28.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sushi-3.28.3-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"totem-3.26.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"totem-devel-3.26.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"totem-nautilus-3.26.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"totem-pl-parser-3.26.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"totem-pl-parser-devel-3.26.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"upower-0.99.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"upower-devel-0.99.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"upower-devel-docs-0.99.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vala-0.40.8-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vala-devel-0.40.8-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vala-doc-0.40.8-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"valadoc-0.40.8-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"valadoc-devel-0.40.8-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vino-3.22.0-7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vte-profile-0.52.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vte291-0.52.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vte291-devel-0.52.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"wayland-devel-1.15.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"wayland-doc-1.15.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"wayland-protocols-devel-1.14-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"webkitgtk4-2.20.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"webkitgtk4-devel-2.20.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"webkitgtk4-doc-2.20.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"webkitgtk4-jsc-2.20.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"webkitgtk4-jsc-devel-2.20.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"webkitgtk4-plugin-process-gtk2-2.20.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xdg-desktop-portal-1.0.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xdg-desktop-portal-devel-1.0.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xdg-desktop-portal-gtk-1.0.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yelp-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yelp-devel-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yelp-libs-3.28.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yelp-tools-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yelp-xsl-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yelp-xsl-devel-3.28.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"zenity-3.28.1-1.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PackageKit / PackageKit-command-not-found / PackageKit-cron / etc");
}
