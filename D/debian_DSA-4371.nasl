#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4371. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121317);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/25");

  script_cve_id("CVE-2019-3462");
  script_xref(name:"DSA", value:"4371");

  script_name(english:"Debian DSA-4371-1 : apt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Max Justicz discovered a vulnerability in APT, the high level package
manager. The code handling HTTP redirects in the HTTP transport method
doesn't properly sanitize fields transmitted over the wire. This
vulnerability could be used by an attacker located as a
man-in-the-middle between APT and a mirror to inject malicous content
in the HTTP connection. This content could then be recognized as a
valid package by APT and used later for code execution with root
privileges on the target machine.

Since the vulnerability is present in the package manager itself, it
is recommended to disable redirects in order to prevent exploitation
during this upgrade only, using :

apt -o Acquire::http::AllowRedirect=false update apt -o
Acquire::http::AllowRedirect=false upgrade

This is known to break some proxies when used against
security.debian.org. If that happens, people can switch their security
APT source to use the URL linked in the advisory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/apt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/apt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4371"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apt packages.

For the stable distribution (stretch), this problem has been fixed in
version 1.4.9.

Specific upgrade instructions :

If upgrading using APT without redirect is not possible in your
situation, you can manually download the files (using wget/curl) for
your architecture using the URL provided in the advisory, verifying
that the hashes match. Then you can install them using dpkg -i."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"apt", reference:"1.4.9")) flag++;
if (deb_check(release:"9.0", prefix:"apt-doc", reference:"1.4.9")) flag++;
if (deb_check(release:"9.0", prefix:"apt-transport-https", reference:"1.4.9")) flag++;
if (deb_check(release:"9.0", prefix:"apt-utils", reference:"1.4.9")) flag++;
if (deb_check(release:"9.0", prefix:"libapt-inst2.0", reference:"1.4.9")) flag++;
if (deb_check(release:"9.0", prefix:"libapt-pkg-dev", reference:"1.4.9")) flag++;
if (deb_check(release:"9.0", prefix:"libapt-pkg-doc", reference:"1.4.9")) flag++;
if (deb_check(release:"9.0", prefix:"libapt-pkg5.0", reference:"1.4.9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
