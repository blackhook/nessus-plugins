#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102121);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2017-1093");
  script_bugtraq_id(95891);

  script_name(english:"AIX bellmail Advisory : bellmail_advisory2.asc (IV92238) (IV92240) (IV92241) (IV92242) (IV92250)");
  script_summary(english:"Checks the version of the bellmail packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of bellmail installed that is
affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of bellmail installed on the remote AIX host is affected
by a privilege escalation vulnerability. A local attacker can exploit
this to gain root privileges.");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/bellmail_advisory2.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1093");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:bellmail:bellmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item("Host/AIX/version");
if (isnull(oslevel)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevel = oslevel - "AIX-";

oslevelcomplete = chomp(get_kb_item("Host/AIX/oslevelsp"));
if (isnull(oslevelcomplete)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevelparts = split(oslevelcomplete, sep:'-', keep:0);
if ( max_index(oslevelparts) != 4 ) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
ml = oslevelparts[1];
sp = oslevelparts[2];

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

aix_bellmail_vulns = {
  "6.1": {
    "09": {
      "06": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.200",
          "patch":"(IV92238m8a)"
        }
      },
      "07": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.200",
          "patch":"(IV92238m8a|IV97356m9a)"
        }
      },
      "08": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.200",
          "patch":"(IV92238m8a|IV97356m9a)"
        }
      }
    }
  },
  "7.1": {
    "03": {
      "05": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.45",
          "patch":"(IV92250m71)"
        }
      },
      "06": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.46",
          "patch":"(IV92250m71)"
        }
      },
      "07": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.47",
          "patch":"(IV92250m71)"
        }
      }
    },
    "04": {
      "01": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.30",
          "patch":"(IV92240m3a)"
        }
      },
      "02": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.30",
          "patch":"(IV92240m3a)"
        }
      },
      "03": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.30",
          "patch":"(IV92240m3a|IV99497m5a)"
        }
      }
    }
  },
  "7.2": {
   "00": {
      "00": {
        "bos.net.tcp.client_core": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.2",
          "patch":"(IV92241m2a)"
        }
      },
      "01": {
        "bos.net.tcp.client_core": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.2",
          "patch":"(IV92241m2a)"
        }
      },
      "02": {
        "bos.net.tcp.client_core": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.2",
          "patch":"(IV92241m2a)"
        }
      }
    },
   "01": {
      "00": {
        "bos.net.tcp.client_core": {
          "minfilesetver":"7.2.1.0",
          "maxfilesetver":"7.2.1.1",
          "patch":"(IV92242m1a)"
        }
      },
      "01": {
        "bos.net.tcp.client_core": {
          "minfilesetver":"7.2.1.0",
          "maxfilesetver":"7.2.1.1",
          "patch":"(IV92242m1a|IV99499m3a)"
        }
      }
    }
  }
};

version_report = "AIX " + oslevel;
if ( empty_or_null(aix_bellmail_vulns[oslevel]) ) {
  os_options = join( sort( keys(aix_bellmail_vulns) ), sep:' / ' );
  audit(AUDIT_OS_NOT, os_options, version_report);
}

version_report = version_report + " ML " + ml;
if ( empty_or_null(aix_bellmail_vulns[oslevel][ml]) ) {
  ml_options = join( sort( keys(aix_bellmail_vulns[oslevel]) ), sep:' / ' );
  audit(AUDIT_OS_NOT, "ML " + ml_options, version_report);
}

version_report = version_report + " SP " + sp;
if ( empty_or_null(aix_bellmail_vulns[oslevel][ml][sp]) ) {
  sp_options = join( sort( keys(aix_bellmail_vulns[oslevel][ml]) ), sep:' / ' );
  audit(AUDIT_OS_NOT, "SP " + sp_options, version_report);
}

foreach package ( keys(aix_bellmail_vulns[oslevel][ml][sp]) ) {
  package_info = aix_bellmail_vulns[oslevel][ml][sp][package];
  minfilesetver = package_info["minfilesetver"];
  maxfilesetver = package_info["maxfilesetver"];
  patch =         package_info["patch"];
  if (aix_check_ifix(release:oslevel, ml:ml, sp:sp, patch:patch, package:package, minfilesetver:minfilesetver, maxfilesetver:maxfilesetver) < 0) flag++;
}

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : aix_report_extra
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bos.net.tcp.client / bos.net.tcp.client_core");
}
