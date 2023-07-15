#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4115. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106854);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2018-5378", "CVE-2018-5379", "CVE-2018-5380", "CVE-2018-5381");
  script_xref(name:"DSA", value:"4115");
  script_xref(name:"CEA-ID", value:"CEA-2019-0227");

  script_name(english:"Debian DSA-4115-1 : quagga - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in Quagga, a routing
daemon. The Common Vulnerabilities and Exposures project identifies
the following issues :

  - CVE-2018-5378
    It was discovered that the Quagga BGP daemon, bgpd, does
    not properly bounds check data sent with a NOTIFY to a
    peer, if an attribute length is invalid. A configured
    BGP peer can take advantage of this bug to read memory
    from the bgpd process or cause a denial of service
    (daemon crash).

  https://www.quagga.net/security/Quagga-2018-0543.txt

  - CVE-2018-5379
    It was discovered that the Quagga BGP daemon, bgpd, can
    double-free memory when processing certain forms of
    UPDATE message, containing cluster-list and/or unknown
    attributes, resulting in a denial of service (bgpd
    daemon crash).

  https://www.quagga.net/security/Quagga-2018-1114.txt

  - CVE-2018-5380
    It was discovered that the Quagga BGP daemon, bgpd, does
    not properly handle internal BGP code-to-string
    conversion tables.

  https://www.quagga.net/security/Quagga-2018-1550.txt

  - CVE-2018-5381
    It was discovered that the Quagga BGP daemon, bgpd, can
    enter an infinite loop if sent an invalid OPEN message
    by a configured peer. A configured peer can take
    advantage of this flaw to cause a denial of service
    (bgpd daemon not responding to any other events; BGP
    sessions will drop and not be reestablished;
    unresponsive CLI interface).

  https://www.quagga.net/security/Quagga-2018-1975.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-5378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-5379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-5380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-5381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/quagga"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/quagga"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/quagga"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4115"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the quagga packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 0.99.23.1-1+deb8u5.

For the stable distribution (stretch), these problems have been fixed
in version 1.1.1-3+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:quagga");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

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
if (deb_check(release:"8.0", prefix:"quagga", reference:"0.99.23.1-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"quagga-dbg", reference:"0.99.23.1-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"quagga-doc", reference:"0.99.23.1-1+deb8u5")) flag++;
if (deb_check(release:"9.0", prefix:"quagga", reference:"1.1.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-bgpd", reference:"1.1.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-core", reference:"1.1.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-doc", reference:"1.1.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-isisd", reference:"1.1.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-ospf6d", reference:"1.1.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-ospfd", reference:"1.1.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-pimd", reference:"1.1.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-ripd", reference:"1.1.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-ripngd", reference:"1.1.1-3+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
