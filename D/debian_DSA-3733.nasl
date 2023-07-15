#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3733. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95777);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-1252");
  script_xref(name:"DSA", value:"3733");

  script_name(english:"Debian DSA-3733-1 : apt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jann Horn of Google Project Zero discovered that APT, the high level
package manager, does not properly handle errors when validating
signatures on InRelease files. An attacker able to man-in-the-middle
HTTP requests to an apt repository that uses InRelease files
(clearsigned Release files), can take advantage of this flaw to
circumvent the signature of the InRelease file, leading to arbitrary
code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/apt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3733"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apt packages.

For the stable distribution (jessie), this problem has been fixed in
version 1.0.9.8.4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/14");
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
if (deb_check(release:"8.0", prefix:"apt", reference:"1.0.9.8.4")) flag++;
if (deb_check(release:"8.0", prefix:"apt-doc", reference:"1.0.9.8.4")) flag++;
if (deb_check(release:"8.0", prefix:"apt-transport-https", reference:"1.0.9.8.4")) flag++;
if (deb_check(release:"8.0", prefix:"apt-utils", reference:"1.0.9.8.4")) flag++;
if (deb_check(release:"8.0", prefix:"libapt-inst1.5", reference:"1.0.9.8.4")) flag++;
if (deb_check(release:"8.0", prefix:"libapt-pkg-dev", reference:"1.0.9.8.4")) flag++;
if (deb_check(release:"8.0", prefix:"libapt-pkg-doc", reference:"1.0.9.8.4")) flag++;
if (deb_check(release:"8.0", prefix:"libapt-pkg4.12", reference:"1.0.9.8.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
