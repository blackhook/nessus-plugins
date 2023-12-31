#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-88-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82233);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2011-0188", "CVE-2011-2686", "CVE-2011-2705", "CVE-2011-4815", "CVE-2014-8080", "CVE-2014-8090");
  script_bugtraq_id(46950, 46966, 49015, 51198, 70935, 71230);

  script_name(english:"Debian DLA-88-1 : ruby1.8 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes multiple local and remote denial of service and
remote code execute problems :

CVE-2011-0188 Properly allocate memory, to prevent arbitrary code
execution or application crash. Reported by Drew Yao.

CVE-2011-2686

Reinitialize the random seed when forking to prevent CVE-2003-0900
like situations.

CVE-2011-2705 Modify PRNG state to prevent random number sequence
repeatation at forked child process which has same pid. Reported by
Eric Wong.

CVE-2011-4815

Fix a problem with predictable hash collisions resulting in denial of
service (CPU consumption) attacks. Reported by Alexander Klink and
Julian Waelde.

CVE-2014-8080

Fix REXML parser to prevent memory consumption denial of service via
crafted XML documents. Reported by Willis Vandevanter.

CVE-2014-8090

Add REXML::Document#document to complement the fix for CVE-2014-8080.
Reported by Tomas Hoger.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/11/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/ruby1.8"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libruby1.8-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtcltk-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ri1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.8-elisp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.8-examples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libruby1.8", reference:"1.8.7.302-2squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libruby1.8-dbg", reference:"1.8.7.302-2squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libtcltk-ruby1.8", reference:"1.8.7.302-2squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"ri1.8", reference:"1.8.7.302-2squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"ruby1.8", reference:"1.8.7.302-2squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"ruby1.8-dev", reference:"1.8.7.302-2squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"ruby1.8-elisp", reference:"1.8.7.302-2squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"ruby1.8-examples", reference:"1.8.7.302-2squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
