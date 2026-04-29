"""
jurisdiction_helpers.py — SynJuris v2
Centralized jurisdiction statute resolution and alias mapping.
"""

# Mapping of states to primary custody, support, and DV statutes
JURISDICTION_LAW = {
    "Alabama":        {"custody": "Ala. Code § 30-3-1", "support": "Ala. Code § 30-3-110", "dv": "Ala. Code § 30-5-1"},
    "Alaska":         {"custody": "Alaska Stat. § 25.20.060", "support": "Alaska Stat. § 25.27.020", "dv": "Alaska Stat. § 18.66.100"},
    "Arizona":        {"custody": "A.R.S. § 25-403", "support": "A.R.S. § 25-501", "dv": "A.R.S. § 13-3601"},
    "Arkansas":       {"custody": "Ark. Code § 9-13-101", "support": "Ark. Code § 9-14-201", "dv": "Ark. Code § 9-15-201"},
    "California":     {"custody": "Cal. Fam. Code § 3020", "support": "Cal. Fam. Code § 4050", "dv": "Cal. Fam. Code § 6200"},
    "Colorado":       {"custody": "C.R.S. § 14-10-124", "support": "C.R.S. § 14-14-104", "dv": "C.R.S. § 13-14-101"},
    "Connecticut":    {"custody": "C.G.S. § 46b-56", "support": "C.G.S. § 46b-84", "dv": "C.G.S. § 46b-15"},
    "Delaware":       {"custody": "13 Del. C. § 722", "support": "13 Del. C. § 514", "dv": "10 Del. C. § 1041"},
    "Florida":        {"custody": "Fla. Stat. § 61.13", "support": "Fla. Stat. § 61.29", "dv": "Fla. Stat. § 741.28"},
    "Georgia":        {"custody": "O.C.G.A. § 19-9-1", "support": "O.C.G.A. § 19-6-15", "dv": "O.C.G.A. § 19-13-1"},
    "Hawaii":         {"custody": "HRS § 571-46", "support": "HRS § 576D-1", "dv": "HRS § 586-1"},
    "Idaho":          {"custody": "Idaho Code § 32-717", "support": "Idaho Code § 32-706", "dv": "Idaho Code § 39-6301"},
    "Illinois":       {"custody": "750 ILCS 5/602.5", "support": "750 ILCS 5/505", "dv": "750 ILCS 60/101"},
    "Indiana":        {"custody": "I.C. § 31-17-2-8", "support": "I.C. § 31-16-6-1", "dv": "I.C. § 34-26-5-1"},
    "Iowa":           {"custody": "Iowa Code § 598.41", "support": "Iowa Code § 598.21B", "dv": "Iowa Code § 236.2"},
    "Kansas":         {"custody": "K.S.A. § 23-3203", "support": "K.S.A. § 23-3001", "dv": "K.S.A. § 60-3101"},
    "Kentucky":       {"custody": "KRS § 403.270", "support": "KRS § 403.212", "dv": "KRS § 403.715"},
    "Louisiana":      {"custody": "La. C.C. Art. 132", "support": "La. R.S. § 9:315", "dv": "La. R.S. § 46:2131"},
    "Maine":          {"custody": "19-A M.R.S. § 1653", "support": "19-A M.R.S. § 2006", "dv": "19-A M.R.S. § 4001"},
    "Maryland":       {"custody": "Md. Code, FL § 9-101", "support": "Md. Code, FL § 12-201", "dv": "Md. Code, FL § 4-501"},
    "Massachusetts":  {"custody": "M.G.L. c.208 § 31", "support": "M.G.L. c.208 § 28", "dv": "M.G.L. c.209A § 1"},
    "Michigan":       {"custody": "MCL § 722.23", "support": "MCL § 552.451", "dv": "MCL § 600.2950"},
    "Minnesota":      {"custody": "Minn. Stat. § 518.17", "support": "Minn. Stat. § 518A.26", "dv": "Minn. Stat. § 518B.01"},
    "Mississippi":    {"custody": "Miss. Code § 93-5-24", "support": "Miss. Code § 93-9-1", "dv": "Miss. Code § 93-21-1"},
    "Missouri":       {"custody": "Mo. Rev. Stat. § 452.375", "support": "Mo. Rev. Stat. § 452.340", "dv": "Mo. Rev. Stat. § 455.010"},
    "Montana":        {"custody": "MCA § 40-4-212", "support": "MCA § 40-5-201", "dv": "MCA § 40-15-101"},
    "Nebraska":       {"custody": "Neb. Rev. Stat. § 43-2923", "support": "Neb. Rev. Stat. § 42-364", "dv": "Neb. Rev. Stat. § 42-903"},
    "Nevada":         {"custody": "NRS § 125C.0035", "support": "NRS § 125B.010", "dv": "NRS § 33.018"},
    "New Hampshire":  {"custody": "RSA § 461-A:6", "support": "RSA § 458-C:3", "dv": "RSA § 173-B:1"},
    "New Jersey":     {"custody": "N.J.S.A. § 9:2-4", "support": "N.J.S.A. § 2A:34-23", "dv": "N.J.S.A. § 2C:25-17"},
    "New Mexico":     {"custody": "NMSA § 40-4-9.1", "support": "NMSA § 40-4-11.1", "dv": "NMSA § 40-13-1"},
    "New York":       {"custody": "N.Y. Dom. Rel. Law § 240", "support": "N.Y. Fam. Ct. Act § 413", "dv": "N.Y. Fam. Ct. Act § 812"},
    "North Carolina": {"custody": "N.C.G.S. § 50-13.2", "support": "N.C.G.S. § 50-13.4", "dv": "N.C.G.S. § 50B-1"},
    "North Dakota":   {"custody": "N.D.C.C. § 14-09-06.2", "support": "N.D.C.C. § 14-09-09.7", "dv": "N.D.C.C. § 14-07.1-01"},
    "Ohio":           {"custody": "ORC § 3109.04", "support": "ORC § 3119.02", "dv": "ORC § 3113.31"},
    "Oklahoma":       {"custody": "43 O.S. § 112", "support": "43 O.S. § 118", "dv": "22 O.S. § 60.1"},
    "Oregon":         {"custody": "ORS § 107.137", "support": "ORS § 107.105", "dv": "ORS § 107.700"},
    "Pennsylvania":   {"custody": "23 Pa.C.S. § 5328", "support": "23 Pa.C.S. § 4322", "dv": "23 Pa.C.S. § 6101"},
    "Rhode Island":   {"custody": "R.I. Gen. Laws § 15-5-16", "support": "R.I. Gen. Laws § 15-5-16.2", "dv": "R.I. Gen. Laws § 15-15-1"},
    "South Carolina": {"custody": "S.C. Code § 63-15-230", "support": "S.C. Code § 63-17-470", "dv": "S.C. Code § 20-4-20"},
    "South Dakota":   {"custody": "SDCL § 25-5-7.1", "support": "SDCL § 25-7-6.2", "dv": "SDCL § 25-10-1"},
    "Tennessee":      {"custody": "TN Code § 36-6-101", "support": "TN Code § 36-5-101", "dv": "TN Code § 36-3-601"},
    "Texas":          {"custody": "Tex. Fam. Code § 153.002", "support": "Tex. Fam. Code § 154.001", "dv": "Tex. Fam. Code § 71.004"},
    "Utah":           {"custody": "Utah Code § 30-3-10", "support": "Utah Code § 78B-12-202", "dv": "Utah Code § 77-36-1"},
    "Vermont":        {"custody": "15 V.S.A. § 665", "support": "15 V.S.A. § 653", "dv": "15 V.S.A. § 1101"},
    "Virginia":       {"custody": "Va. Code § 20-124.3", "support": "Va. Code § 20-108.2", "dv": "Va. Code § 16.1-228"},
    "Washington":     {"custody": "RCW § 26.09.187", "support": "RCW § 26.19.020", "dv": "RCW § 26.50.010"},
    "West Virginia":  {"custody": "W. Va. Code § 48-9-206", "support": "W. Va. Code § 48-13-301", "dv": "W. Va. Code § 48-27-202"},
    "Wisconsin":      {"custody": "Wis. Stat. § 767.41", "support": "Wis. Stat. § 767.511", "dv": "Wis. Stat. § 813.12"},
    "Wyoming":        {"custody": "Wyo. Stat. § 20-2-201", "support": "Wyo. Stat. § 20-2-304", "dv": "Wyo. Stat. § 35-21-102"},
    "Washington D.C.":{"custody": "D.C. Code § 16-914", "support": "D.C. Code § 16-916", "dv": "D.C. Code § 16-1001"},
}

JURISDICTION_ALIASES = {
    "al":"Alabama","ak":"Alaska","az":"Arizona","ar":"Arkansas","ca":"California",
    "co":"Colorado","ct":"Connecticut","de":"Delaware","fl":"Florida","ga":"Georgia",
    "hi":"Hawaii","id":"Idaho","il":"Illinois","in":"Indiana","ia":"Iowa","ks":"Kansas",
    "ky":"Kentucky","la":"Louisiana","me":"Maine","md":"Maryland","ma":"Massachusetts",
    "mi":"Michigan","mn":"Minnesota","ms":"Mississippi","mo":"Missouri","mt":"Montana",
    "ne":"Nebraska","nv":"Nevada","nh":"New Hampshire","nj":"New Jersey","nm":"New Mexico",
    "ny":"New York","nc":"North Carolina","nd":"North Dakota","oh":"Ohio","ok":"Oklahoma",
    "or":"Oregon","pa":"Pennsylvania","ri":"Rhode Island","sc":"South Carolina",
    "sd":"South Dakota","tn":"Tennessee","tx":"Texas","ut":"Utah","vt":"Vermont",
    "va":"Virginia","wa":"Washington","wv":"West Virginia","wi":"Wisconsin","wy":"Wyoming",
    "dc":"Washington D.C.","d.c.":"Washington D.C.",
    "tenn":"Tennessee","tenn.":"Tennessee","calif":"California","calif.":"California",
    "colo":"Colorado","conn":"Connecticut","mass":"Massachusetts","mich":"Michigan",
    "minn":"Minnesota","penn":"Pennsylvania","wisc":"Wisconsin",
}

def resolve_jurisdiction(raw):
    """Clean up user input and return canonical state name and statutes."""
    if not raw:
        return None, {}
    key = raw.strip().lower()
    canonical = JURISDICTION_ALIASES.get(key) or next(
        (k for k in JURISDICTION_LAW if k.lower() == key), None
    )
    if canonical:
        return canonical, JURISDICTION_LAW.get(canonical, {})
    for k in JURISDICTION_LAW:
        if k.lower() in key:
            return k, JURISDICTION_LAW[k]
    return raw.title(), {}

def jurisdiction_statute_block(jurisdiction):
    """Generate a text block for inclusion in AI prompts or document headers."""
    name, statutes = resolve_jurisdiction(jurisdiction)
    if not statutes:
        return (f"Jurisdiction: {name}\n"
                "(Specific statute codes not available — describe general legal principles "
                "and encourage user to verify their state's laws.)")
    lines = [f"Jurisdiction: {name}"]
    if statutes.get("custody"):
        lines.append(f"  Custody statute:   {statutes['custody']}")
    if statutes.get("support"):
        lines.append(f"  Support statute:   {statutes['support']}")
    if statutes.get("dv"):
        lines.append(f"  DV/protection:     {statutes['dv']}")
    return "\n".join(lines)
