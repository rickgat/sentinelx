/**
 * Shared types for the in-app Help / Tutorial submenu.
 *
 * The Help section is a 9-page hierarchy:
 *   - /dashboard/help                (index — search + category cards)
 *   - /dashboard/help/getting-started
 *   - /dashboard/help/posture
 *   - /dashboard/help/discovery
 *   - /dashboard/help/identity
 *   - /dashboard/help/soc-detection
 *   - /dashboard/help/offensive
 *   - /dashboard/help/governance
 *   - /dashboard/help/integrations
 *
 * Each category page is composed of N `MenuTutorial` blocks — one block
 * per dashboard route the category owns. The schema is intentionally
 * flat so non-engineers can author new content without learning React.
 */

export interface MenuTutorialCrossRef {
  /** Display label, e.g. "PRD §6A.3" or "/dashboard/findings". */
  label: string;
  /** Internal (`/dashboard/...`) or external URL. */
  href: string;
}

export interface MenuTutorialFaq {
  /** Question, phrased as the user would think it. */
  q: string;
  /** Short answer (markdown allowed). */
  a: string;
}

export interface MenuTutorial {
  /** Stable anchor id, used by the sticky TOC. e.g. "findings". */
  id: string;
  /** Human-readable menu name, e.g. "Findings". */
  title: string;
  /** The dashboard route this tutorial documents, e.g. "/dashboard/findings". */
  route: string;
  /** 1-2 sentence "Purpose" paragraph. */
  purpose: string;
  /** 2-3 bullets describing trigger conditions. */
  whenToUse: ReadonlyArray<string>;
  /** 3-7 numbered steps describing the canonical workflow. */
  workflow: ReadonlyArray<string>;
  /** What data feeds the menu (API endpoints, ingest paths). */
  inputs: ReadonlyArray<string>;
  /** What artefacts the menu produces (rows, exports, side effects). */
  outputs: ReadonlyArray<string>;
  /** RBA role names that gate this menu (analyst / admin / ops). */
  roles: ReadonlyArray<string>;
  /** 2-3 FAQ items handling likely confusion. */
  faqs: ReadonlyArray<MenuTutorialFaq>;
  /** Internal + external cross-references. */
  references: ReadonlyArray<MenuTutorialCrossRef>;
}

export interface HelpCategory {
  /** URL slug under `/dashboard/help/`. */
  slug: string;
  /** Display title. */
  title: string;
  /** 1-sentence summary used on the index card. */
  summary: string;
  /** Lucide icon name (resolved by index page). */
  icon: string;
}
