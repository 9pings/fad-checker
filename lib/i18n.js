/**
 * lib/i18n.js — report localisation (en / fr), selected by --lang.
 *
 * The ENGLISH STRING IS THE KEY. `t("Copy table")` returns the French wording under
 * `fr` and the key itself under `en`, so:
 *   - the English report is byte-identical to the one that existed before this file,
 *     which is what makes a 850-test suite asserting exact strings still meaningful;
 *   - a missing translation degrades to English instead of rendering a raw key at a
 *     client, which is the failure mode of every id-keyed catalogue;
 *   - the catalogue reads as a glossary and can be reviewed by someone who does not
 *     read the code.
 *
 * SCOPE: the report's own chrome only. Text that comes from a data source — CVE
 * descriptions, advisory summaries, registry deprecation reasons, endoflife notes — is
 * NEVER translated: it is evidence, and paraphrasing evidence in an audit is wrong.
 * CWE titles are the one exception (see data/cwe-names-fr.json): they are a fixed
 * vocabulary, and MITRE's original travels with every translated one.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

const LOCALES = ["en", "fr"];

/** "us", "en-US", "EN" … → "en"; "fr-FR" → "fr"; anything else → "en". */
function normaliseLocale(raw) {
	const s = String(raw || "").trim().toLowerCase().replace("_", "-");
	if (!s) return "en";
	const base = s.split("-")[0];
	if (base === "us") return "en";
	return LOCALES.includes(base) ? base : "en";
}

// French wording for the report's chrome. Keys are the English source strings.
// Identifiers (CVE, GHSA, EPSS, KEV, SHA-256, CWE ids) are deliberately absent: they
// are names, not prose, and fall through to English.
const fr = {
	"Copy the executive summary \u2014 paste it into Word with formatting preserved": "Copier la synth\u00e8se \u2014 se colle dans Word en conservant la mise en forme",
	"Copy this chart as a PNG \u2014 paste it into Word": "Copier ce graphique en PNG \u2014 se colle dans Word",
	"Copied!": "Copi\u00e9 !",
	"Copy failed": "\u00c9chec de la copie",
	"Executive Summary": "Synth\u00e8se",
	"Copy summary": "Copier la synth\u00e8se",
	"dependencies scanned": "d\u00e9pendances analys\u00e9es",
	"most critical \u00b7 direct production dependencies": "les plus critiques \u00b7 d\u00e9pendances de production directes",
	"Top end-of-life framework": "Framework en fin de vie le plus critique",
	"end-of-life frameworks": "frameworks en fin de vie",
	"production CVE": "CVE de production",
	"dev/test CVE": "CVE de dev/test",
	"vulnerable vendored-JS": "JS embarqu\u00e9 vuln\u00e9rable",
	"EOL framework": "framework en fin de vie",
	"EOL frameworks": "frameworks en fin de vie",
	"unmanaged native binary": "binaire natif non g\u00e9r\u00e9",
	"unmanaged native binaries": "binaires natifs non g\u00e9r\u00e9s",
	"EOL since": "en fin de vie depuis",
	"end-of-life": "en fin de vie",
	"support ended": "support termin\u00e9",
	"latest": "derni\u00e8re",
	"out of active support": "hors support actif",
	"transitive": "transitive",
	"Production": "Production",
	"Vendored JS vulns": "Vuln\u00e9rabilit\u00e9s JS embarqu\u00e9",
	"Dev dependencies": "D\u00e9pendances de d\u00e9veloppement",
	"Likely false positives \u2014 CPE-filtered": "Faux positifs probables \u2014 filtr\u00e9s par CPE",
	"Embedded binaries": "Binaires embarqu\u00e9s",
	"Unmanaged / vendored native binaries": "Binaires natifs non g\u00e9r\u00e9s / embarqu\u00e9s",
	"Unmanaged / vendored JavaScript": "JavaScript non g\u00e9r\u00e9 / embarqu\u00e9",
	"Obsolete / deprecated": "Obsol\u00e8tes / d\u00e9pr\u00e9ci\u00e9es",
	"Fix Recommendations": "Recommandations de correction",
	"Scanned dependency descriptors": "Descripteurs de d\u00e9pendances analys\u00e9s",
	"Ignored directories": "R\u00e9pertoires ignor\u00e9s",
	"Methodology, data sources & limitations": "M\u00e9thodologie, sources de donn\u00e9es et limites",
	"All": "Toutes",
	"All \u2014 direct": "Toutes \u2014 directes",
	"All \u2014 transitive": "Toutes \u2014 transitives",
	"Direct deps to update": "Deps directes \u00e0 mettre \u00e0 jour",
	"End-of-Life frameworks": "Frameworks en fin de vie",
	"End-of-Life / out-of-support frameworks": "Frameworks en fin de vie / hors support",
	"out of support": "hors support",
	"Warnings & scan-completeness": "Avertissements et compl\u00e9tude du scan",
	"FAD-Checker Report": "Rapport FAD-Checker",
	"Multi-ecosystem dependency security audit": "Audit de s\u00e9curit\u00e9 des d\u00e9pendances, multi-\u00e9cosyst\u00e8me",
	"Project:": "Projet :",
	"Generated:": "G\u00e9n\u00e9r\u00e9 le :",
	"CVE data:": "Donn\u00e9es CVE :",
	"Executive Summary": "Synth\u00e8se",
	"Everything else:": "Tout le reste :",
	"Copy summary": "Copier la synth\u00e8se",
	"Copy table": "Copier le tableau",
	"Copy chart": "Copier le graphique",
	"Copy this table \u2014 paste it into Word with formatting preserved": "Copier ce tableau \u2014 se colle dans Word en conservant la mise en forme",
	"Copy only part of this table": "Copier seulement une partie de ce tableau",
	"First 5 rows": "Les 5 premi\u00e8res lignes",
	"Critical only": "Critiques uniquement",
	"Critical + high": "Critiques + \u00e9lev\u00e9es",
	"Exploited (KEV) only": "Exploit\u00e9es (KEV) uniquement",
	"Expand all": "Tout d\u00e9plier",
	"Collapse all": "Tout replier",
	"Expand all CVE details": "D\u00e9plier le d\u00e9tail des CVE",
	"Collapse all CVE details": "Replier le d\u00e9tail des CVE",
	"Click a section header or a CVE row to toggle.": "Cliquez sur un titre de section ou une ligne CVE pour la d\u00e9plier.",
	"Print": "Imprimer",
	"Jump": "Aller \u00e0",
	"Priority / severity": "Priorit\u00e9 / s\u00e9v\u00e9rit\u00e9",
	"CVE ID": "Identifiant CVE",
	"Dependency": "D\u00e9pendance",
	"Description": "Description",
	"Fix Version": "Version corrig\u00e9e",
	"Fix version": "Version corrig\u00e9e",
	"Source": "Source",
	"Sources": "Sources",
	"Recommended action": "Action recommand\u00e9e",
	"Severity": "S\u00e9v\u00e9rit\u00e9",
	"Sev": "S\u00e9v.",
	"Max Sev": "S\u00e9v. max",
	"Worst sev": "Pire s\u00e9v.",
	"Worst transitive sev": "Pire s\u00e9v. transitive",
	"Priority": "Priorit\u00e9",
	"Published": "Publi\u00e9e le",
	"Product": "Produit",
	"EOL date": "Date de fin de vie",
	"Latest": "Derni\u00e8re",
	"Notes": "Notes",
	"Obsolete": "Obsol\u00e8te",
	"Replacement": "Remplacement",
	"Why": "Pourquoi",
	"Current": "Actuelle",
	"Released": "Publi\u00e9e",
	"Version": "Version",
	"Library": "Biblioth\u00e8que",
	"Vendored file": "Fichier embarqu\u00e9",
	"File": "Fichier",
	"Type": "Type",
	"State": "\u00c9tat",
	"Status": "Statut",
	"Ecosystem": "\u00c9cosyst\u00e8me",
	"Category": "Cat\u00e9gorie",
	"License(s)": "Licence(s)",
	"Algorithm": "Algorithme",
	"Detection": "D\u00e9tection",
	"Detail": "D\u00e9tail",
	"Details": "D\u00e9tails",
	"Summary": "R\u00e9sum\u00e9",
	"Findings": "Constats",
	"Matched": "Correspondance",
	"Resolved": "R\u00e9solue",
	"Modified": "Modifi\u00e9e",
	"Rule": "R\u00e8gle",
	"Data source": "Source de donn\u00e9es",
	"As of": "Au",
	"Fixed in": "Corrig\u00e9e dans",
	"Direct dependency": "D\u00e9pendance directe",
	"Direct deps": "Deps directes",
	"Transitive (current)": "Transitive (actuelle)",
	"Transitive CVE": "CVE transitive",
	"Vulnerable transitives": "Transitives vuln\u00e9rables",
	"Brought in by": "Apport\u00e9e par",
	"All dependency chains": "Toutes les cha\u00eenes de d\u00e9pendances",
	"Update path": "Chemin de mise \u00e0 jour",
	"Declared in": "D\u00e9clar\u00e9e dans",
	"Descriptor": "Descripteur",
	"Weaknesses (CWE)": "Faiblesses (CWE)",
	"CWE": "CWE",
	"Affected CPE configurations": "Configurations CPE affect\u00e9es",
	"Match confidence": "Confiance de la correspondance",
	"Metadata": "M\u00e9tadonn\u00e9es",
	"Aliases": "Alias",
	"External links": "Liens externes",
	"CVE detail:": "D\u00e9tail CVE :",
	"CVEs covered": "CVE couvertes",
	"Base score": "Score de base",
	"CVSS base score": "Score de base CVSS",
	"Identity (by checksum)": "Identit\u00e9 (par empreinte)",
	"SHA-256": "SHA-256",
	"Coordinate (groupId:artifactId:version)": "Coordonn\u00e9e (groupId:artifactId:version)",
	"Directory (relative to --src)": "R\u00e9pertoire (relatif \u00e0 --src)",
	"Maven Central latest": "Derni\u00e8re sur Maven Central",
	"New": "Nouvelle",
	"Unchanged": "Inchang\u00e9e",
	"New CVE findings:": "Nouveaux constats CVE :",
	"Pin to \u2265": "\u00c9pingler \u00e0 \u2265",
	"No CVE matches.": "Aucune CVE trouv\u00e9e.",
	"No CVEs matched.": "Aucune CVE trouv\u00e9e.",
	"No CPE-filtered findings.": "Aucun constat filtr\u00e9 par CPE.",
	"No end-of-life frameworks detected.": "Aucun framework en fin de vie d\u00e9tect\u00e9.",
	"No obsolete / deprecated libraries detected.": "Aucune biblioth\u00e8que obsol\u00e8te ou d\u00e9pr\u00e9ci\u00e9e d\u00e9tect\u00e9e.",
	"No outdated libraries (or --allLibs not set).": "Aucune biblioth\u00e8que en retard (ou --allLibs non activ\u00e9).",
	"No vendored JavaScript libraries identified.": "Aucune biblioth\u00e8que JavaScript embarqu\u00e9e identifi\u00e9e.",
	"No committed native binaries found.": "Aucun binaire natif versionn\u00e9 trouv\u00e9.",
	"No committed certificates or key material found.": "Aucun certificat ni mat\u00e9riel cryptographique versionn\u00e9 trouv\u00e9.",
	"No embedded JAR/WAR/EAR coordinates found.": "Aucune coordonn\u00e9e JAR/WAR/EAR embarqu\u00e9e trouv\u00e9e.",
	"No directories were excluded from the scan.": "Aucun r\u00e9pertoire n'a \u00e9t\u00e9 exclu du scan.",
	"No actionable recommendations.": "Aucune recommandation actionnable.",
	"No provenance manifest available for this run.": "Aucun manifeste de provenance pour cette ex\u00e9cution.",
	"(unknown weakness)": "(faiblesse inconnue)",
	"How this report was produced and what it does": "Comment ce rapport a \u00e9t\u00e9 produit et ce qu'il",
	"Limitations \u2014 fad-checker does not assess:": "Limites \u2014 fad-checker n'\u00e9value pas :",
	"Reachability / exploitability in your app.": "L'atteignabilit\u00e9 ou l'exploitabilit\u00e9 dans votre application.",
	"Business-logic & first-party code flaws.": "Les failles de logique m\u00e9tier et du code propri\u00e9taire.",
	"Runtime configuration & mitigations.": "La configuration d'ex\u00e9cution et les mesures d'att\u00e9nuation.",
	"Secrets, IaC & container base images.": "Les secrets, l'IaC et les images de base de conteneurs.",
	"Malware beyond the available signal.": "Les logiciels malveillants au-del\u00e0 du signal disponible.",
	"License legal advice.": "Le conseil juridique sur les licences.",
	"Private / internal coordinates.": "Les coordonn\u00e9es priv\u00e9es ou internes.",
	"Data-source recency.": "La fra\u00eecheur des sources de donn\u00e9es.",
	"CWE \u2014 direct vulns (by criticality)": "CWE \u2014 vuln\u00e9rabilit\u00e9s directes (par criticit\u00e9)",
	"Sub-dep CVEs per dependency": "CVE de sous-d\u00e9pendances par d\u00e9pendance",
	"Most vulnerable components": "Composants les plus vuln\u00e9rables",
	"Direct vs transitive (by severity)": "Directes vs transitives (par s\u00e9v\u00e9rit\u00e9)",
	"Fix priority": "Priorit\u00e9 de correction",
	"No categorised direct CVE.": "Aucune CVE directe cat\u00e9goris\u00e9e.",
	"No vulnerable transitive deps.": "Aucune d\u00e9pendance transitive vuln\u00e9rable.",
	"No critical or high production CVE.": "Aucune CVE critique ou \u00e9lev\u00e9e en production.",
	"No production CVE.": "Aucune CVE en production.",
	"Direct": "Directes",
	"Transitive": "Transitives",
	"Exploited": "Exploit\u00e9es",
	"Critical": "Critiques",
	"High": "\u00c9lev\u00e9es",
	"Medium": "Moyennes",
	"Low": "Faibles",
	"Unknown": "Inconnue",
	"KEV exploited": "Exploit\u00e9es (KEV)",
	"Total CVEs": "Total CVE",
	"in Direct": "En direct",
	"in Transitive": "En transitif",
	"Vendored JS": "JS embarqu\u00e9",
	"EOL": "Fin de vie",
	"Outdated": "En retard",
	"Licenses to review": "Licences \u00e0 revoir",
	"Scan alerts": "Alertes de scan",
	"CVE data": "Donn\u00e9es CVE",
	"Warnings": "Avertissements",
	"CVE": "CVE",
	"Unmanaged components": "Composants non g\u00e9r\u00e9s",
	"Maintenance/EOL": "Maintenance/Fin de vie",
	"Licenses": "Licences",
	"Fix Recos": "Recommandations",
	"Scan context": "Contexte du scan",
	"Prod": "Prod",
	"Dev": "Dev",
	"Likely FP": "Faux positifs probables",
	"Embedded": "Embarqu\u00e9s",
	"Native": "Natifs",
	"Crypto": "Cryptographie",
	"Descriptors": "Descripteurs",
	"Ignored dirs": "R\u00e9pertoires ignor\u00e9s",
	"Methodology": "M\u00e9thodologie",
	"dependencies scanned": "d\u00e9pendances analys\u00e9es",
};

const CATALOG = { en: {}, fr };

/**
 * Translator for one locale. `vars` interpolates {name} placeholders, so a sentence
 * can be reordered in translation instead of being concatenated in source order.
 */
function makeT(locale) {
	const loc = normaliseLocale(locale);
	const table = CATALOG[loc] || CATALOG.en;
	return function t(key, vars) {
		let out = (loc !== "en" && table[key] != null) ? table[key] : key;
		if (vars) for (const [k, v] of Object.entries(vars)) out = out.split(`{${k}}`).join(String(v));
		return out;
	};
}

module.exports = { LOCALES, normaliseLocale, makeT, CATALOG };
