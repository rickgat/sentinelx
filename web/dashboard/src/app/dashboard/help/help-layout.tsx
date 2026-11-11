import Link from "next/link";
import { ChevronRight, ExternalLink } from "lucide-react";
import ReactMarkdown from "react-markdown";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

import type { MenuTutorial } from "./help-types";

/**
 * Renders one category page composed of `tutorials.length` `MenuTutorial`
 * blocks plus a sticky right-hand table of contents. Each block produces
 * deep-linkable anchors (`#purpose`, `#workflow`, …) prefixed by the
 * tutorial id so multiple tutorials on the same page never collide.
 *
 * Markdown is used for FAQ answers and cross-reference rendering — every
 * tutorial section is otherwise plain text + bullets to keep the schema
 * authorable without React knowledge.
 */
interface HelpCategoryLayoutProps {
  category: string;
  title: string;
  intro: string;
  tutorials: ReadonlyArray<MenuTutorial>;
}

export function HelpCategoryLayout({
  category,
  title,
  intro,
  tutorials,
}: HelpCategoryLayoutProps) {
  return (
    <div className="space-y-4">
      <Breadcrumb category={title} />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{title}</CardTitle>
          <CardDescription className="text-sm">{intro}</CardDescription>
        </CardHeader>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_220px]">
        <div className="space-y-6">
          {tutorials.map((t) => (
            <TutorialBlock key={t.id} category={category} tutorial={t} />
          ))}
        </div>
        <aside className="hidden lg:block">
          <div className="sticky top-20 space-y-1">
            <p className="px-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              On this page
            </p>
            <ul className="space-y-0.5 text-sm">
              {tutorials.map((t) => (
                <li key={t.id}>
                  <a
                    href={`#${t.id}`}
                    className="block rounded-sx px-2 py-1 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
                  >
                    {t.title}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </aside>
      </div>
    </div>
  );
}

function Breadcrumb({ category }: { category: string }) {
  return (
    <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-xs text-muted-foreground">
      <Link href="/dashboard/help" className="hover:text-foreground transition-colors">
        Help
      </Link>
      <ChevronRight className="h-3 w-3" aria-hidden />
      <span className="text-foreground">{category}</span>
    </nav>
  );
}

function TutorialBlock({
  category,
  tutorial,
}: {
  category: string;
  tutorial: MenuTutorial;
}) {
  void category;
  const id = tutorial.id;
  return (
    <Card id={id} className="scroll-mt-20">
      <CardHeader className="space-y-1">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-base">{tutorial.title}</CardTitle>
          <div className="flex flex-wrap items-center gap-1">
            {tutorial.roles.map((r) => (
              <Badge key={r} variant="info">
                role: {r}
              </Badge>
            ))}
            {tutorial.route.includes("[") ? (
              <span
                className="inline-flex items-center gap-1 rounded-sx border border-border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground"
                title="Dynamic route — open from the parent list view"
              >
                Dynamic
              </span>
            ) : (
              <Link
                href={tutorial.route}
                prefetch={false}
                className="inline-flex items-center gap-1 rounded-sx border border-border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground hover:bg-muted hover:text-foreground"
              >
                Open
                <ExternalLink className="h-3 w-3" aria-hidden />
              </Link>
            )}
          </div>
        </div>
        <CardDescription className="text-xs">{tutorial.route}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        <Section id={`${id}-purpose`} title="Purpose">
          <p className="text-foreground">{tutorial.purpose}</p>
        </Section>

        <Section id={`${id}-when`} title="When to use">
          <ul className="list-disc space-y-1 pl-5 text-foreground">
            {tutorial.whenToUse.map((b, i) => (
              <li key={i}>{b}</li>
            ))}
          </ul>
        </Section>

        <Section id={`${id}-workflow`} title="Step-by-step workflow">
          <ol className="list-decimal space-y-1 pl-5 text-foreground">
            {tutorial.workflow.map((b, i) => (
              <li key={i}>{b}</li>
            ))}
          </ol>
        </Section>

        <Section id={`${id}-io`} title="Inputs and outputs">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                Inputs
              </p>
              <ul className="mt-1 list-disc space-y-1 pl-5 text-foreground">
                {tutorial.inputs.map((b, i) => (
                  <li key={i}>{b}</li>
                ))}
              </ul>
            </div>
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                Outputs
              </p>
              <ul className="mt-1 list-disc space-y-1 pl-5 text-foreground">
                {tutorial.outputs.map((b, i) => (
                  <li key={i}>{b}</li>
                ))}
              </ul>
            </div>
          </div>
        </Section>

        <Section id={`${id}-faq`} title="FAQ and pitfalls">
          <div className="space-y-2">
            {tutorial.faqs.map((f, i) => (
              <details
                key={i}
                className="rounded-sx border border-border bg-background/50 px-3 py-2"
              >
                <summary className="cursor-pointer text-sm font-medium text-foreground">
                  {f.q}
                </summary>
                <div className="mt-2 text-xs text-muted-foreground prose-headings:text-foreground prose-strong:text-foreground prose-a:text-accent">
                  <ReactMarkdown>{f.a}</ReactMarkdown>
                </div>
              </details>
            ))}
          </div>
        </Section>

        <Section id={`${id}-refs`} title="Cross-references">
          <ul className="flex flex-wrap gap-2">
            {tutorial.references.map((r, i) => (
              <li key={i}>
                <Link
                  href={r.href}
                  prefetch={false}
                  className="inline-flex items-center gap-1 rounded-sx border border-border px-2 py-1 text-xs text-muted-foreground hover:bg-muted hover:text-foreground"
                >
                  {r.label}
                </Link>
              </li>
            ))}
          </ul>
        </Section>
      </CardContent>
    </Card>
  );
}

function Section({
  id,
  title,
  children,
}: {
  id: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section aria-labelledby={id} className="space-y-2 scroll-mt-20">
      <h2
        id={id}
        className="text-xs font-semibold uppercase tracking-wider text-muted-foreground"
      >
        {title}
      </h2>
      {children}
    </section>
  );
}
