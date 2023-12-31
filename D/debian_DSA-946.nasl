#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-946. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22812);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-4158", "CVE-2006-0151");
  script_bugtraq_id(16184);
  script_xref(name:"DSA", value:"946");

  script_name(english:"Debian DSA-946-2 : sudo - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The former correction to vulnerabilities in the sudo package worked
fine but were too strict for some environments. Therefore we have
reviewed the changes again and allowed some environment variables to
go back into the privileged execution environment. Hence, this update.

The configuration option 'env_reset' is now activated by default. It
will preserve only the environment variables HOME, LOGNAME, PATH,
SHELL, TERM, DISPLAY, XAUTHORITY, XAUTHORIZATION, LANG, LANGUAGE,
LC_*, and USER in addition to the separate SUDO_* variables.

For completeness please find below the original advisory text :

  It has been discovered that sudo, a privileged program, that
  provides limited super user privileges to specific users, passes
  several environment variables to the program that runs with elevated
  privileges. In the case of include paths (e.g. for Perl, Python,
  Ruby or other scripting languages) this can cause arbitrary code to
  be executed as privileged user if the attacker points to a
  manipulated version of a system library.

  This update alters the former behaviour of sudo and limits the
  number of supported environment variables to LC_*, LANG, LANGUAGE
  and TERM. Additional variables are only passed through when set as
  env_check in /etc/sudoers, which might be required for some scripts
  to continue to work."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=342948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-946"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the sudo package. For unstable 'Defaults = env_reset' need to
be added to /etc/sudoers manually.

For the old stable distribution (woody) this problem has been fixed in
version 1.6.6-1.6.

For the stable distribution (sarge) this problem has been fixed in
version 1.6.8p7-1.4."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"sudo", reference:"1.6.6-1.6")) flag++;
if (deb_check(release:"3.1", prefix:"sudo", reference:"1.6.8p7-1.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
