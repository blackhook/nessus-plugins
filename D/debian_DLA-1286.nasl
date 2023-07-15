#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1286-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106873);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2018-5379", "CVE-2018-5380", "CVE-2018-5381");
  script_xref(name:"CEA-ID", value:"CEA-2019-0227");

  script_name(english:"Debian DLA-1286-1 : quagga security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Several vulnerabilities have been discovered in Quagga, a routing
daemon. The Common Vulnerabilities and Exposures project identifies
the following issues :

CVE-2018-5378

It was discovered that the Quagga BGP daemon, bgpd, does not properly
bounds check data sent with a NOTIFY to a peer, if an attribute length
is invalid. A configured BGP peer can take advantage of this bug to
read memory from the bgpd process or cause a denial of service (daemon
crash).

https://www.quagga.net/security/Quagga-2018-0543.txt

CVE-2018-5379

It was discovered that the Quagga BGP daemon, bgpd, can double-free
memory when processing certain forms of UPDATE message, containing
cluster-list and/or unknown attributes, resulting in a denial of
service (bgpd daemon crash).

https://www.quagga.net/security/Quagga-2018-1114.txt

CVE-2018-5380

It was discovered that the Quagga BGP daemon, bgpd, does not properly
handle internal BGP code-to-string conversion tables.

https://www.quagga.net/security/Quagga-2018-1550.txt

CVE-2018-5381

It was discovered that the Quagga BGP daemon, bgpd, can enter an
infinite loop if sent an invalid OPEN message by a configured peer. A
configured peer can take advantage of this flaw to cause a denial of
service (bgpd daemon not responding to any other events; BGP sessions
will drop and not be reestablished; unresponsive CLI interface).

https://www.quagga.net/security/Quagga-2018-1975.txt

For Debian 7 'Wheezy', these problems have been fixed in version
0.99.22.4-1+wheezy3+deb7u3.

We recommend that you upgrade your quagga packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2018/02/msg00021.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/wheezy/quagga");
  script_set_attribute(attribute:"see_also", value:"https://www.quagga.net/security/Quagga-2018-0543.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.quagga.net/security/Quagga-2018-1114.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.quagga.net/security/Quagga-2018-1550.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.quagga.net/security/Quagga-2018-1975.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected quagga, quagga-dbg, and quagga-doc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:quagga-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:quagga-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"quagga", reference:"0.99.22.4-1+wheezy3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"quagga-dbg", reference:"0.99.22.4-1+wheezy3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"quagga-doc", reference:"0.99.22.4-1+wheezy3+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
