#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3454. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88423);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-5307", "CVE-2015-8104", "CVE-2016-0495", "CVE-2016-0592");
  script_xref(name:"DSA", value:"3454");

  script_name(english:"Debian DSA-3454-1 : virtualbox - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in VirtualBox, an x86
virtualisation solution.

Upstream support for the 4.1 release series has ended and since no
information is available which would allow backports of isolated
security fixes, security support for virtualbox in wheezy/oldstable
needed to be ended as well. If you use virtualbox with externally
procured VMs (e.g. through vagrant) we advise you to update to Debian
jessie."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/virtualbox"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3454"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the virtualbox packages.

For the stable distribution (jessie), these problems have been fixed
in version 4.3.36-dfsg-1+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"virtualbox", reference:"4.3.36-dfsg-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox-dbg", reference:"4.3.36-dfsg-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox-dkms", reference:"4.3.36-dfsg-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox-guest-dkms", reference:"4.3.36-dfsg-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox-guest-source", reference:"4.3.36-dfsg-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox-guest-utils", reference:"4.3.36-dfsg-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox-guest-x11", reference:"4.3.36-dfsg-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox-qt", reference:"4.3.36-dfsg-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox-source", reference:"4.3.36-dfsg-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
