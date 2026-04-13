package locale

import (
	"os"
	"strings"
)

// Lang represents a supported language.
type Lang string

const (
	EN Lang = "en"
	ES Lang = "es"
)

// current holds the active language. Defaults to auto-detected.
var current = detect()

// Set overrides the current language.
func Set(l Lang) { current = l }

// Current returns the active language.
func Current() Lang { return current }

// detect reads LANG/LC_ALL from the environment.
func detect() Lang {
	for _, key := range []string{"GUARD_LANG", "LC_ALL", "LANG"} {
		v := os.Getenv(key)
		if strings.HasPrefix(v, "es") {
			return ES
		}
	}
	return EN
}

// T returns the translated string for the given key.
func T(key string) string {
	m, ok := messages[current]
	if !ok {
		m = messages[EN]
	}
	if s, ok := m[key]; ok {
		return s
	}
	// Fallback to English
	if s, ok := messages[EN][key]; ok {
		return s
	}
	return key
}

var messages = map[Lang]map[string]string{
	EN: {
		// ── General ──
		"app.name":    "Guard",
		"app.tagline": "Supply chain guardrail for pnpm projects",
		"app.version": "guard %s",
		"done":        "Done.",
		"error":       "Error",
		"warning":     "Warning",

		// ── Help ──
		"help.usage":        "Usage",
		"help.commands":     "Commands",
		"help.global_flags": "Global Flags",
		"help.examples":     "Examples",
		"help.aliases":      "Aliases",
		"help.hint_lang":    "Tip: Set GUARD_LANG=es for Spanish output",
		"help.hint_init":    "Tip: Run 'guard init' to set up a secure baseline",
		"help.hint_scan":    "Tip: Run 'guard scan' to check your repo",

		// ── Commands ──
		"cmd.init":         "Set up a secure baseline",
		"cmd.init.long":    "Creates .guard/policy.yaml, hardens pnpm-workspace.yaml,\nand generates a CI workflow + contributor docs.",
		"cmd.scan":         "Scan the repository for issues",
		"cmd.scan.long":    "Checks repo structure, pnpm settings, and GitHub workflow hygiene.",
		"cmd.ci":           "Strict scan for CI pipelines",
		"cmd.ci.long":      "Same as scan but with stricter defaults for automated environments.",
		"cmd.diff":         "Compare two package versions",
		"cmd.diff.long":    "Analyzes risk signals between two versions of a package.",
		"cmd.fix":          "Auto-fix issues found by scan",
		"cmd.approve":      "Approve a package build script",
		"cmd.approve.long": "Registers an explicit exception for packages that need install scripts.",
		"cmd.version":      "Print version",
		"cmd.help":         "Show this help",

		// ── Init ──
		"init.start":        "Setting up Guard baseline...",
		"init.created":      "  Created",
		"init.exists":       "  Exists (skipped)",
		"init.would_create": "  Would create",
		"init.done":         "Baseline ready! Run 'guard scan' to verify.",
		"init.done_dryrun":  "Dry run complete. No files were written.",
		"init.already":      "Guard is already set up here. Use --force to overwrite.",

		// ── Scan ──
		"scan.start":         "Scanning repository...",
		"scan.checking":      "  Checking",
		"scan.repo":          "repo structure",
		"scan.pnpm":          "pnpm settings",
		"scan.workflows":     "GitHub workflows",
		"scan.policy":        "policy exceptions",
		"scan.scoring":       "scoring",
		"scan.pass":          "All clear! No blocking issues found.",
		"scan.fail":          "Issues found that need attention.",
		"scan.summary":       "%d blocking, %d warnings, %d info",
		"scan.hint_fix":      "Run with --format json for machine-readable output.",
		"scan.no_findings":   "No findings — your repo looks good!",
		"scan.next_steps":    "Next steps",
		"scan.step_required": "(required — blocks CI)",
		"scan.step_optional": "(recommended)",
		"scan.hint_rescan":   "After fixing, run 'guard scan' again to verify.",

		// ── CI ──
		"ci.start": "Running CI checks...",
		"ci.pass":  "CI passed — no blocking findings.",
		"ci.fail":  "CI failed — blocking findings detected.",

		// ── Diff ──
		"diff.start":       "Comparing %s@%s → %s...",
		"diff.clean":       "No risk signals detected. Looks safe!",
		"diff.risky":       "Risk signals detected — review before updating.",
		"diff.critical":    "Critical risk! Manual review strongly recommended.",
		"diff.no_registry": "Registry download not yet available. Use --from-dir and --to-dir for local comparison.",

		// ── Fix ──
		"fix.scanning":  "Scanning for fixable issues...",
		"fix.nothing":   "Nothing to fix — everything looks good!",
		"fix.no_auto":   "No auto-fixable issues found.",
		"fix.plan":      "Fix plan",
		"fix.manual":    "Manual steps",
		"fix.confirm":   "Run these fixes? (y/N) ",
		"fix.running":   "Running fixes",
		"fix.done":      "%d fixes applied successfully.",
		"fix.partial":   "%d fixes applied, %d failed.",
		"fix.cancelled": "Cancelled — no changes made.",

		// ── Approve ──
		"approve.start":   "Approving build for %s...",
		"approve.done":    "Build approved for %s.",
		"approve.updated": "  Updated",
		"approve.would":   "  Would update",

		// ── Findings ──
		"finding.blocking": "BLOCKING",
		"finding.warning":  "WARNING",
		"finding.info":     "INFO",
		"finding.muted":    "MUTED",
		"finding.fix":      "Fix",
		"finding.run":      "Run",
		"finding.file":     "File",

		// ── Severities ──
		"severity.critical": "CRITICAL",
		"severity.high":     "HIGH",
		"severity.medium":   "MEDIUM",
		"severity.low":      "LOW",

		// ── Decision ──
		"decision.pass": "PASS",
		"decision.fail": "FAIL",
	},

	ES: {
		// ── General ──
		"app.name":    "Guard",
		"app.tagline": "Guardia de supply chain para proyectos pnpm",
		"app.version": "guard %s",
		"done":        "Listo.",
		"error":       "Error",
		"warning":     "Advertencia",

		// ── Help ──
		"help.usage":        "Uso",
		"help.commands":     "Comandos",
		"help.global_flags": "Flags Globales",
		"help.examples":     "Ejemplos",
		"help.aliases":      "Alias",
		"help.hint_lang":    "Tip: Usá GUARD_LANG=en para salida en inglés",
		"help.hint_init":    "Tip: Corré 'guard init' para configurar una base segura",
		"help.hint_scan":    "Tip: Corré 'guard scan' para revisar tu repo",

		// ── Commands ──
		"cmd.init":         "Configurar una base segura",
		"cmd.init.long":    "Crea .guard/policy.yaml, endurece pnpm-workspace.yaml,\ny genera un workflow de CI + docs para contribuidores.",
		"cmd.scan":         "Escanear el repositorio",
		"cmd.scan.long":    "Revisa estructura del repo, settings de pnpm e higiene de workflows.",
		"cmd.ci":           "Escaneo estricto para CI",
		"cmd.ci.long":      "Igual que scan pero con defaults más estrictos para pipelines.",
		"cmd.diff":         "Comparar dos versiones de un paquete",
		"cmd.diff.long":    "Analiza señales de riesgo entre dos versiones de un paquete.",
		"cmd.fix":          "Arreglar problemas encontrados por scan",
		"cmd.approve":      "Aprobar un build script",
		"cmd.approve.long": "Registra una excepción explícita para paquetes que necesitan scripts de instalación.",
		"cmd.version":      "Mostrar versión",
		"cmd.help":         "Mostrar esta ayuda",

		// ── Init ──
		"init.start":        "Configurando baseline de Guard...",
		"init.created":      "  Creado",
		"init.exists":       "  Existe (omitido)",
		"init.would_create": "  Se crearía",
		"init.done":         "¡Baseline lista! Corré 'guard scan' para verificar.",
		"init.done_dryrun":  "Simulación completa. No se escribieron archivos.",
		"init.already":      "Guard ya está configurado acá. Usá --force para sobreescribir.",

		// ── Scan ──
		"scan.start":         "Escaneando repositorio...",
		"scan.checking":      "  Revisando",
		"scan.repo":          "estructura del repo",
		"scan.pnpm":          "settings de pnpm",
		"scan.workflows":     "workflows de GitHub",
		"scan.policy":        "excepciones de policy",
		"scan.scoring":       "puntuación",
		"scan.pass":          "¡Todo bien! No se encontraron problemas bloqueantes.",
		"scan.fail":          "Se encontraron problemas que necesitan atención.",
		"scan.summary":       "%d bloqueantes, %d advertencias, %d info",
		"scan.hint_fix":      "Corré con --format json para salida procesable.",
		"scan.no_findings":   "Sin hallazgos — ¡tu repo se ve bien!",
		"scan.next_steps":    "Próximos pasos",
		"scan.step_required": "(requerido — bloquea CI)",
		"scan.step_optional": "(recomendado)",
		"scan.hint_rescan":   "Después de arreglar, corré 'guard scan' de nuevo.",

		// ── CI ──
		"ci.start": "Ejecutando chequeos de CI...",
		"ci.pass":  "CI pasó — sin hallazgos bloqueantes.",
		"ci.fail":  "CI falló — se detectaron hallazgos bloqueantes.",

		// ── Diff ──
		"diff.start":       "Comparando %s@%s → %s...",
		"diff.clean":       "No se detectaron señales de riesgo. ¡Se ve seguro!",
		"diff.risky":       "Se detectaron señales de riesgo — revisá antes de actualizar.",
		"diff.critical":    "¡Riesgo crítico! Se recomienda revisión manual.",
		"diff.no_registry": "Descarga del registry no disponible aún. Usá --from-dir y --to-dir para comparación local.",

		// ── Approve ──
		// ── Fix ──
		"fix.scanning":  "Buscando problemas para arreglar...",
		"fix.nothing":   "Nada que arreglar — ¡todo se ve bien!",
		"fix.no_auto":   "No se encontraron problemas auto-reparables.",
		"fix.plan":      "Plan de arreglos",
		"fix.manual":    "Pasos manuales",
		"fix.confirm":   "¿Ejecutar estos arreglos? (s/N) ",
		"fix.running":   "Ejecutando arreglos",
		"fix.done":      "%d arreglos aplicados correctamente.",
		"fix.partial":   "%d arreglos aplicados, %d fallaron.",
		"fix.cancelled": "Cancelado — no se hicieron cambios.",

		// ── Approve ──
		"approve.start":   "Aprobando build para %s...",
		"approve.done":    "Build aprobado para %s.",
		"approve.updated": "  Actualizado",
		"approve.would":   "  Se actualizaría",

		// ── Findings ──
		"finding.blocking": "BLOQUEANTE",
		"finding.warning":  "ADVERTENCIA",
		"finding.info":     "INFO",
		"finding.muted":    "SILENCIADO",
		"finding.fix":      "Solución",
		"finding.run":      "Corré",
		"finding.file":     "Archivo",

		// ── Severities ──
		"severity.critical": "CRÍTICO",
		"severity.high":     "ALTO",
		"severity.medium":   "MEDIO",
		"severity.low":      "BAJO",

		// ── Decision ──
		"decision.pass": "PASÓ",
		"decision.fail": "FALLÓ",
	},
}
