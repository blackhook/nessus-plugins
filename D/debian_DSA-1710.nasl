#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1710. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35461);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0241");
  script_xref(name:"DSA", value:"1710");

  script_name(english:"Debian DSA-1710-1 : ganglia-monitor-core - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Spike Spiegel discovered a stack-based buffer overflow in gmetad, the
meta-daemon for the ganglia cluster monitoring toolkit, which could be
triggered via a request with long path names and might enable
arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2009/dsa-1710"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ganglia-monitor-core packages.

For the stable distribution (etch), this problem has been fixed in
version 2.5.7-3.1etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ganglia-monitor-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"4.0", prefix:"ganglia-monitor", reference:"2.5.7-3.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gmetad", reference:"2.5.7-3.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libganglia1", reference:"2.5.7-3.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libganglia1-dev", reference:"2.5.7-3.1etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
