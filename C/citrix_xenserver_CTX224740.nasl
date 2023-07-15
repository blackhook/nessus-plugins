#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101205);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id(
    "CVE-2017-10911",
    "CVE-2017-10912",
    "CVE-2017-10913",
    "CVE-2017-10914",
    "CVE-2017-10915",
    "CVE-2017-10917",
    "CVE-2017-10918",
    "CVE-2017-10920",
    "CVE-2017-10921",
    "CVE-2017-10922"
  );
  script_bugtraq_id(
    99157,
    99158,
    99161,
    99162,
    99174,
    99411,
    99435
  );

  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX224740)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"A server virtualization platform installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer installed on the remote host is
missing a security hotfix. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists that causes grant table operations to fail
    due to improper handling of reference counts. An
    unauthenticated, remote attacker can exploit this to
    have an unspecified impact.

  - An information disclosure vulnerability exists due to
    blkif responses leaking stack data. An unauthenticated,
    remote attacker can exploit this to disclose potentially
    sensitive information.

  - A NULL pointer dereference flaw exists in the event
    channel poll that allows an unauthenticated, remote
    attacker to cause a denial of service condition.

  - A flaw exists in shadow emulation due to insufficient
    reference counts. An unauthenticated, remote attacker
    can exploit this to have an unspecified impact.

  - A race condition exists in the grant table unmap code
    that allows an unauthenticated, remote attacker to have
    an unspecified impact.

  - An unspecified flaw exists in page transfers that allows
    a local attacker on the PV guest to gain elevated
    privileges.

  - A flaw exists that is triggered by stale P2M mappings
    due to insufficient error checking. An unauthenticated,
    remote attacker can exploit this to have an unspecified
    impact.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX224740");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10921");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_xenserver_version.nbin");
  script_require_keys("Host/XenServer/version", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Citrix XenServer";
version = get_kb_item_or_exit("Host/XenServer/version");
get_kb_item_or_exit("Host/local_checks_enabled");
patches = get_kb_item("Host/XenServer/patches");
vuln = FALSE;
fix = '';

# two hotfixes for each series
if (version == "6.0.2")
{
  fix = "XS602ECC045"; # CTX224687
  if (fix >!< patches) vuln = TRUE;

  if (!vuln)
  {
    fix = "XS602ECC046"; # CTX224693
    if (fix >!< patches) vuln = TRUE;
  }
}
else if (version =~ "^6\.2\.0")
{
  fix = "XS62ESP1061"; # CTX224688
  if (fix >!< patches) vuln = TRUE;

  if (!vuln)
  {
    fix = "XS62ESP1062"; # CTX224694
    if (fix >!< patches) vuln = TRUE;
  }
}
else if (version =~ "^6\.5($|[^0-9])")
{
  fix = "XS65ESP1057"; # CTX224689
  if (fix >!< patches) vuln = TRUE;

  if (!vuln)
  {
    fix = "XS65ESP1058"; # CTX224695
    if (fix >!< patches) vuln = TRUE;
  }
}
else if (version =~ "^7\.0($|[^0-9])")
{
  fix = "XS70E035"; # CTX224690
  if (fix >!< patches) vuln = TRUE;

  if (!vuln)
  {
    fix = "XS70E036"; # CTX224696
    if (fix >!< patches) vuln = TRUE;
  }
}
else if (version =~ "^7\.1($|[^0-9])")
{
  fix = "XS71E011"; # CTX224691
  if (fix >!< patches && "XS71ECU" >!< patches) vuln = TRUE;

  if (!vuln)
  {
    fix = "XS71E012"; # CTX224697
    if (fix >!< patches && "XS71ECU" >!< patches) vuln = TRUE;
  }
}
else if (version =~ "^7\.2($|[^0-9])")
{
  fix = "XS72E001"; # CTX224692
  if (fix >!< patches) vuln = TRUE;

  if (!vuln)
  {
    fix = "XS72E002"; # CTX224698
    if (fix >!< patches) vuln = TRUE;
  }
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (vuln)
{
  port = 0;
  report = report_items_str(
    report_items:make_array(
      "Installed version", version,
      "Missing hotfix", fix
    ),
    ordered_fields:make_list("Installed version", "Missing hotfix")
  );
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_PATCH_INSTALLED, fix);
